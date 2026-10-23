"""Laufzeitmessung der Lieferkette, ein Lauf je Ausbaustufe.

Gemessen wird mit time.perf_counter(). Die Uhr ist monoton und hat die
höchste verfügbare Auflösung. Verwendet werden nur Differenzen zweier Aufrufe.

Messgrößen (in Sekunden):
  build      Distribute-PipelineRun angelegt bis abgeschlossen. Enthält in der
             verifizierbaren Kette die Prüftasks (AN1 bis AN3) und die
             Stückliste (AN5).
  nachweis   Build abgeschlossen bis Tekton Chains den Herkunftsnachweis
             signiert hat (AN4). Nur in der verifizierbaren Kette.
  deploy     Deploy-PipelineRun angelegt bis der neue Pod läuft. Enthält in der
             verifizierbaren Kette die Zulassungskontrolle (AN6, AN7).
  zulassung  Antwortzeit des API-Servers auf das Anlegen eines Pods mit dem
             laufenden Image (Probelauf mit --dry-run=server). In der
             verifizierbaren Kette mit Kyverno und Prüfdienst.
  gesamt     build + nachweis + deploy

Zusätzlich wird die Dateigröße der Artefakte in Bytes gemessen. Die Werte
stammen aus den Manifesten in der Registry. Dort ist für jede Datei (Blob)
ihre exakte Größe angegeben.
  groesse_image        komprimierte Layer und Konfiguration des Images,
                       also die Dateien, die beim Pull übertragen werden
  groesse_stueckliste  die Datei sbom.cdx.json, Tag sha256-<digest>.sbom (AN5)
  groesse_nachweis     der signierte Herkunftsnachweis (DSSE-Umschlag als
                       JSON-Datei), Tag sha256-<digest>.att (AN4)
Stückliste und Nachweis gibt es nur in der verifizierbaren Kette.

Genauigkeit: Der Abschluss eines PipelineRuns wird alle POLL Sekunden über
kubectl abgefragt. Die Messwerte sind daher auf etwa eine Sekunde genau.

Voraussetzungen: beide Ketten eingerichtet und erreichbar. In der
verifizierbaren Kette ist der aktuelle Stand von main freigegeben (AN2b).

Aufruf im Hauptordner des Repos:
  python3 Measure/measure.py                     # beide Ausbaustufen
  python3 Measure/measure.py --variant hardened  # nur eine
Ergebnis: Ausgabe auf der Konsole und eine Zeile je Lauf in Measure/results.csv.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "Adversarial"))
import lib  # noqa: E402  (Varianten-Konfiguration und kubectl-Helfer)

RESULTS = ROOT / "Measure" / "results.csv"
FIELDS = ["zeitpunkt", "variante", "build", "nachweis", "deploy", "zulassung", "gesamt",
          "groesse_image", "groesse_stueckliste", "groesse_nachweis"]
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json, "
                  "application/vnd.docker.distribution.manifest.v2+json")
POLL = 0.5  # Abfrageintervall in Sekunden


# ---- Helfer ------------------------------------------------------------- #
def get(cfg: dict, *args: str) -> str:
    """kubectl-Abfrage im Kontext der Variante, liefert stdout."""
    return lib.run(lib.kubectl(cfg, *args), check=False).stdout.strip()


def remote_sha(cfg: dict) -> str:
    """Aktueller Commit von main im VCS (Build-Auftrag nach AN2a)."""
    url = (f"http://{cfg['gitea_user']}:{cfg['gitea_password']}"
           f"@{cfg['gitea_host']}/{cfg['repo_path']}")
    out = lib.run(["git", "ls-remote", url, f"refs/heads/{cfg['branch']}"]).stdout
    return out.split()[0]


def start_pipelinerun(cfg: dict, run_file: str, **placeholders: str) -> str:
    """Legt einen PipelineRun an. Platzhalter wie __REVISION__ werden ersetzt."""
    manifest = (ROOT / run_file).read_text()
    for key, value in placeholders.items():
        manifest = manifest.replace(f"__{key}__", value)
    return lib.run(
        lib.kubectl(cfg, "create", "-f", "-", "-o", "jsonpath={.metadata.name}"),
        input=manifest,
    ).stdout.strip()


def wait_until(check, timeout: float, what: str) -> None:
    """Ruft check() alle POLL Sekunden auf, bis es True liefert."""
    deadline = time.perf_counter() + timeout
    while time.perf_counter() < deadline:
        if check():
            return
        time.sleep(POLL)
    raise TimeoutError(f"{what}: nach {timeout} s nicht abgeschlossen")


def wait_pipelinerun(cfg: dict, name: str, timeout: float) -> None:
    def done() -> bool:
        status = get(cfg, "get", "pipelinerun", name,
                     "-o", "jsonpath={.status.conditions[0].status}")
        if status == "False":
            raise RuntimeError(f"PipelineRun {name} fehlgeschlagen")
        return status == "True"
    wait_until(done, timeout, f"PipelineRun {name}")


def wait_signed(cfg: dict, name: str, timeout: float = 300) -> None:
    """Wartet, bis Tekton Chains den PipelineRun als signiert markiert (AN4)."""
    def done() -> bool:
        value = get(cfg, "get", "pipelinerun", name,
                    "-o", r"jsonpath={.metadata.annotations.chains\.tekton\.dev/signed}")
        if value == "failed":
            raise RuntimeError(f"Tekton Chains konnte {name} nicht signieren")
        return value == "true"
    wait_until(done, timeout, f"Herkunftsnachweis zu {name}")


def built_digest(cfg: dict, pipelinerun: str) -> str:
    """Digest des gebauten Images aus dem Result IMAGE_DIGEST des Build-Tasks."""
    return get(cfg, "get", "taskrun",
               "-l", f"tekton.dev/pipelineRun={pipelinerun},tekton.dev/pipelineTask=build-and-push",
               "-o", "jsonpath={.items[0].status.results[?(@.name=='IMAGE_DIGEST')].value}")


def generation(cfg: dict) -> str:
    return get(cfg, "get", "deployment", cfg["deployment"], "-n", cfg["deploy_ns"],
               "-o", "jsonpath={.metadata.generation}")


# ---- Messschritte ------------------------------------------------------- #
def deploy(cfg: dict, build_run: str) -> None:
    """Deploy-Pipeline starten und warten, bis der neue Pod läuft."""
    before = generation(cfg)
    if cfg.get("image_repo"):  # verifizierbare Kette: Image über den Digest (AN6)
        image = f"{cfg['image_repo']}@{built_digest(cfg, build_run)}"
        name = start_pipelinerun(cfg, cfg["deploy_run"], IMAGE=image)
    else:                      # Baseline: Rollout-Restart auf den Tag
        name = start_pipelinerun(cfg, cfg["deploy_run"])
    wait_pipelinerun(cfg, name, timeout=300)
    lib.run(lib.kubectl(cfg, "rollout", "status", f"deployment/{cfg['deployment']}",
                        "-n", cfg["deploy_ns"], "--timeout=180s"))
    if generation(cfg) == before:
        print("    ! Deployment unverändert (gleicher Digest), kein neuer Pod gestartet")


def admission(cfg: dict) -> float:
    """Antwortzeit der Zulassung für einen Pod mit dem laufenden Image."""
    image = get(cfg, "get", "deployment", cfg["deployment"], "-n", cfg["deploy_ns"],
                "-o", "jsonpath={.spec.template.spec.containers[0].image}")
    t0 = time.perf_counter()
    lib.run(lib.kubectl(cfg, "run", "messung-zulassung", "-n", cfg["deploy_ns"],
                        f"--image={image}", "--restart=Never",
                        "--dry-run=server", "-o", "name"))
    return time.perf_counter() - t0


def manifest(api, repo: str, ref: str) -> dict | None:
    status, _, body = api.request("GET", f"/v2/{repo}/manifests/{ref}",
                                  headers={"Accept": MANIFEST_TYPES})
    return json.loads(body) if status == 200 else None


def image_size(api, repo: str, digest: str) -> int | str:
    """Dateigröße des Images: Konfiguration plus alle komprimierten Layer."""
    m = manifest(api, repo, digest)
    return m["config"]["size"] + sum(layer["size"] for layer in m["layers"]) if m else ""


def file_size(api, repo: str, tag: str) -> int | str:
    """Dateigröße eines angehängten Artefakts (Stückliste oder Nachweis).
    Die Datei liegt als Layer unter dem Tag. Fehlt der Tag, bleibt das Feld leer."""
    m = manifest(api, repo, tag)
    if not m:
        return ""
    if len(m["layers"]) > 1:  # mehrere Builds mit demselben Digest
        print(f"    ! {tag}: {len(m['layers'])} Dateien, gemessen wird die neueste")
    return m["layers"][-1]["size"]


def sizes(cfg: dict, digest: str) -> dict:
    """Dateigrößen von Image, Stückliste und Herkunftsnachweis."""
    repo, tag = cfg["registry_repo"], digest.replace(":", "-")
    with lib.registry_api(cfg) as api:
        return {
            "groesse_image": image_size(api, repo, digest),
            "groesse_stueckliste": file_size(api, repo, f"{tag}.sbom"),
            "groesse_nachweis": file_size(api, repo, f"{tag}.att"),
        }


def measure(variant: str) -> dict | None:
    cfg = lib.VARIANTS[variant]
    ok, why = lib.variant_reachable(cfg)
    if not ok:
        print(f"{variant}: übersprungen ({why})")
        return None
    print(f"{variant}: Messlauf startet")

    t0 = time.perf_counter()
    build_run = start_pipelinerun(cfg, cfg["distribute_run"], REVISION=remote_sha(cfg))
    wait_pipelinerun(cfg, build_run, timeout=600)
    t1 = time.perf_counter()
    if variant == "hardened":
        wait_signed(cfg, build_run)
    t2 = time.perf_counter()
    deploy(cfg, build_run)
    t3 = time.perf_counter()

    return {
        "zeitpunkt": datetime.datetime.now().isoformat(timespec="seconds"),
        "variante": variant,
        "build": round(t1 - t0, 1),
        "nachweis": round(t2 - t1, 1) if variant == "hardened" else "",
        "deploy": round(t3 - t2, 1),
        "zulassung": round(admission(cfg), 2),
        "gesamt": round(t3 - t0, 1),
        **sizes(cfg, built_digest(cfg, build_run)),
    }


def save(row: dict) -> None:
    new = not RESULTS.exists()
    if not new:  # ältere Datei mit weniger Spalten: Kopfzeile ergänzen
        with RESULTS.open(newline="") as fh:
            reader = csv.DictReader(fh)
            if reader.fieldnames != FIELDS:
                old = list(reader)
                with RESULTS.open("w", newline="") as out:
                    writer = csv.DictWriter(out, fieldnames=FIELDS, restval="")
                    writer.writeheader()
                    writer.writerows(old)
    with RESULTS.open("a", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=FIELDS)
        if new:
            writer.writeheader()
        writer.writerow(row)


def main() -> int:
    parser = argparse.ArgumentParser(description="Laufzeitmessung der Lieferkette")
    parser.add_argument("--variant", choices=list(lib.VARIANTS),
                        help="nur diese Ausbaustufe messen (Standard: beide)")
    args = parser.parse_args()

    for variant in [args.variant] if args.variant else list(lib.VARIANTS):
        row = measure(variant)
        if row is None:
            continue
        save(row)
        for key in FIELDS[2:]:
            if row[key] == "":
                continue
            if key.startswith("groesse_"):
                print(f"    {key:<20} {row[key] / 1024:>9.1f} KiB")
            else:
                print(f"    {key:<20} {row[key]:>9} s")
    print(f"Ergebnisse angehängt an {RESULTS.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
