"""Gemeinsame Bausteine für die adversarialen Tests.

Enthält die Varianten-Konfigurationen (Baseline / gehärtet), kleine Helfer für
Subprozess-Aufrufe und HTTP-Probes sowie die Basisklasse `AttackTest`, von der
jeder Test erbt. Bewusst schlank: nur Python-Standardbibliothek, keine externen
Abhängigkeiten. Externe Werkzeuge (git, kubectl, tkn) werden per Subprozess
aufgerufen.
"""

from __future__ import annotations

import contextlib
import base64
import hashlib
import socket
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Iterator

# Repo-Wurzel: Adversarial/lib.py -> Adversarial -> <repo>
REPO_ROOT = Path(__file__).resolve().parent.parent


class CommandError(RuntimeError):
    """Ein externes Kommando ist mit Fehlercode beendet worden."""

    def __init__(self, cmd: list[str], returncode: int, stdout: str, stderr: str):
        self.cmd = cmd
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        detail = (stderr or stdout or "").strip().splitlines()
        msg = detail[-1] if detail else ""
        super().__init__(f"`{' '.join(cmd)}` exit {returncode}: {msg}")


def remote_reason(exc: "CommandError") -> str:
    """Begründung des VCS bei einem abgelehnten Push (Zeilen mit "remote:")."""
    lines = [l.split("remote:", 1)[1].strip() for l in (exc.stderr or "").splitlines()
             if l.startswith("remote:") and l.split("remote:", 1)[1].strip()]
    return "; ".join(lines[:2]) or str(exc)


class AttackBlocked(Exception):
    """Die Lieferkette hat die Angriffsaktion verhindert.

    Ein Test wirft dies, wenn er erkennt, dass die Kette den Angriff gestoppt
    hat (z. B. Push abgelehnt oder Pipeline nicht erfolgreich). Für die Baseline
    ist das nicht zu erwarten; für die gehärtete Variante ist es das Ziel.
    """


# Varianten. Der Runner provisioniert nichts, er zielt auf die jeweils bereits
# deployte Kette. Jede Variante läuft in einem eigenen kind-Cluster und wird
# immer über ihren festen kubectl-Kontext angesprochen.
VARIANTS = {
    "baseline": {
        "status": "active",
        "kube_context": "kind-software-supply-chain",
        "gitea_host": "localhost:3000",
        "gitea_user": "VCSadmin",
        "gitea_password": "VCSadmin",
        "repo_path": "VCSadmin/demo-app.git",
        "branch": "main",
        "deploy_ns": "deploy",
        "deployment": "demo-app",
        "registry_namespace": "registry",
        "registry_service": "registry",
        "registry_repo": "demo-app",
        "registry_tag": "latest",
        "container_port": 3000,
        "probe_port": 18080,
        "distribute_run": "Conventional/Distribute/runs/run-gitea.yaml",
        "deploy_run": "Conventional/Deploy/runs/run.yaml",
    },
    "hardened": {
        # Verifizierbare Lieferkette (Verified/). Gleiche Manifeste wie die
        # Baseline, ergänzt um die Prüfungen der verifizierbaren Kette.
        "status": "active",
        "kube_context": "kind-software-supply-chain-verified",
        "gitea_host": "localhost:3001",
        "gitea_user": "VCSadmin",
        "gitea_password": "VCSadmin",
        "repo_path": "VCSadmin/demo-app.git",
        "branch": "main",
        "deploy_ns": "deploy",
        "deployment": "demo-app",
        "registry_namespace": "registry",
        "registry_service": "registry",
        "registry_repo": "demo-app",
        "registry_tag": "latest",
        "container_port": 3000,
        "probe_port": 18081,
        "distribute_run": "Verified/Distribute/runs/run-gitea.yaml",
        # Deploy über den Digest (AN6): der Digest stammt aus dem Distribute-Lauf
        "deploy_run": "Verified/Deploy/runs/run-deploy.yaml",
        "image_repo": "registry.registry.svc.cluster.local:5000/demo-app",
    },
}


def kubectl(cfg: dict, *args: str) -> list[str]:
    """kubectl-Aufruf mit dem festen Kontext der Variante."""
    return ["kubectl", "--context", cfg["kube_context"], *args]


# --------------------------------------------------------------------------- #
# Helfer
# --------------------------------------------------------------------------- #
def run(cmd: list[str], *, cwd=None, check: bool = True, timeout=None, env=None,
        input: str | None = None) -> subprocess.CompletedProcess:
    """Führt ein Kommando aus und liefert das CompletedProcess-Ergebnis.

    Bei check=True und Fehlercode wird CommandError geworfen.
    """
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        timeout=timeout,
        input=input,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise CommandError(cmd, proc.returncode, proc.stdout, proc.stderr)
    return proc


def http_get(url: str, headers: dict | None = None, timeout: int = 10) -> tuple[int, str]:
    """GET auf url, liefert (status, body). HTTP-Fehlercodes werden nicht als
    Ausnahme, sondern als (code, body) zurückgegeben."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def wait_http(url: str, timeout: int = 30, interval: float = 0.5) -> bool:
    """Pollt url, bis Status 200 kommt; sonst TimeoutError nach timeout s."""
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, _ = http_get(url, timeout=3)
            if status == 200:
                return True
        except Exception as exc:  # noqa: BLE001 - Verbindungsfehler beim Poll
            last = exc
        time.sleep(interval)
    raise TimeoutError(f"{url} nicht bereit nach {timeout}s ({last})")


class RegistryAPI:
    """Kleiner HTTP-Client für die OCI-Registry-API v2."""

    def __init__(self, base_url: str, cfg: dict):
        self.base_url = base_url.rstrip("/")
        self.cfg = cfg

    def request(self, method: str, path: str, *, headers: dict | None = None,
                body: bytes | None = None) -> tuple[int, dict[str, str], bytes]:
        """Sendet eine Registry-Anfrage und liefert Status, Header und Inhalt."""
        if path.startswith(("http://", "https://")):
            url = path
        else:
            url = urllib.parse.urljoin(self.base_url + "/", path.lstrip("/"))
        request_headers = dict(headers or {})
        username = self.cfg.get("registry_username")
        password = self.cfg.get("registry_password")
        if username is not None and password is not None:
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            request_headers["Authorization"] = f"Basic {token}"
        request = urllib.request.Request(
            url, data=body, headers=request_headers, method=method
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, dict(response.headers.items()), response.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()

    def upload_blob(self, repository: str, content: bytes) -> str:
        """Lädt einen Blob hoch, sofern er noch nicht in der Registry liegt."""
        digest = f"sha256:{hashlib.sha256(content).hexdigest()}"
        prefix = f"/v2/{repository}/blobs"
        status, _, _ = self.request("HEAD", f"{prefix}/{digest}")
        if status == 200:
            return digest
        if status != 404:
            raise RuntimeError(f"Blob-Prüfung für {digest} lieferte HTTP {status}")

        status, headers, _ = self.request("POST", f"{prefix}/uploads/")
        if status != 202:
            raise RuntimeError(f"Registry-Uploadstart lieferte HTTP {status}")
        location = headers.get("Location") or headers.get("location")
        if not location:
            raise RuntimeError("Registry-Uploadstart lieferte keinen Location-Header")
        upload_url = urllib.parse.urljoin(self.base_url + "/", location)
        parsed_upload = urllib.parse.urlsplit(upload_url)
        parsed_base = urllib.parse.urlsplit(self.base_url)
        query = urllib.parse.parse_qsl(parsed_upload.query, keep_blank_values=True)
        query.append(("digest", digest))
        upload_url = urllib.parse.urlunsplit((
            parsed_base.scheme,
            parsed_base.netloc,
            parsed_upload.path,
            urllib.parse.urlencode(query),
            parsed_upload.fragment,
        ))
        status, _, _ = self.request(
            "PUT", upload_url,
            headers={"Content-Type": "application/octet-stream"},
            body=content,
        )
        if status != 201:
            raise RuntimeError(f"Blob-Upload für {digest} lieferte HTTP {status}")
        return digest


@contextlib.contextmanager
def registry_api(cfg: dict) -> Iterator[RegistryAPI]:
    """Stellt die Registry über einen lokalen kubectl-Port-Forward bereit."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        local_port = listener.getsockname()[1]
    command = kubectl(
        cfg, "port-forward", "--address", "127.0.0.1",
        "-n", cfg.get("registry_namespace", "registry"),
        f"svc/{cfg.get('registry_service', 'registry')}",
        f"{local_port}:5000",
    )
    process = subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    client = RegistryAPI(f"http://127.0.0.1:{local_port}", cfg)
    try:
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError("kubectl-Port-Forward zur Registry wurde beendet")
            try:
                status, _, _ = client.request("GET", "/v2/")
                if status == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(0.2)
        else:
            raise TimeoutError("Registry über Port-Forward nicht erreichbar")
        yield client
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def variant_reachable(cfg: dict) -> tuple[bool, str]:
    """(bool, grund): ist die Kette dieser Variante aktuell erreichbar?"""
    if cfg.get("status") == "pending":
        return False, "Variante noch nicht implementiert"
    try:
        http_get(f"http://{cfg['gitea_host']}/", timeout=3)
    except Exception as exc:  # noqa: BLE001
        return False, f"Gitea nicht erreichbar ({exc})"
    try:
        proc = run(
            kubectl(cfg, "get", "deployment", cfg["deployment"], "-n", cfg["deploy_ns"]),
            check=False,
        )
    except FileNotFoundError:
        return False, "kubectl nicht gefunden"
    if proc.returncode != 0:
        return False, f"Deployment {cfg['deployment']}/{cfg['deploy_ns']} nicht gefunden"
    return True, ""


# --------------------------------------------------------------------------- #
# Basisklasse: bündelt die wiederverwendbaren Angriffs-Bausteine.
# Ein Test erbt hiervon und implementiert attack() / probe() / cleanup().
# --------------------------------------------------------------------------- #
class AttackTest:
    """Basis für einen adversarialen Test gegen eine Varianten-Kette.

    Die Angriffsaktion ist variantenunabhängig; alle Endpunkte (Namespace,
    Gitea-URL, Ports, PipelineRun-Dateien) kommen aus `self.cfg`, damit derselbe
    Test ohne Änderung gegen Baseline und gehärtete Kette läuft.
    """

    META: dict = {}

    def __init__(self, variant: str, cfg: dict):
        self.variant = variant
        self.cfg = cfg
        self.repo_root = REPO_ROOT
        self.detail = ""          # Ergebnis-/Statusmeldung für den Report
        self.repo: Path | None = None
        self._tmpdirs: list[str] = []
        self._image = ""          # gebautes Image mit Digest (verifizierbare Kette)

    # ---- Lebenszyklus (Unterklasse implementiert) ------------------------- #
    def attack(self) -> None:
        raise NotImplementedError

    def probe(self) -> bool:
        raise NotImplementedError

    def cleanup(self) -> None:
        raise NotImplementedError

    # ---- Repo / git ------------------------------------------------------- #
    def push_url(self) -> str:
        c = self.cfg
        return f"http://{c['gitea_user']}:{c['gitea_password']}@{c['gitea_host']}/{c['repo_path']}"

    def clone(self, *, depth: int | None = None) -> Path:
        """Klont das Repo in ein frisches temporäres Verzeichnis (die
        Entwickler-Arbeitskopie bleibt unberührt) und setzt self.repo."""
        tmp = tempfile.mkdtemp(prefix=f"adv-{self.META.get('id', 'test')}-")
        self._tmpdirs.append(tmp)
        target = Path(tmp) / "demo-app"
        cmd = ["git", "clone"]
        if depth:
            cmd += ["--depth", str(depth)]
        cmd += [self.push_url(), str(target)]
        run(cmd)
        self.repo = target
        return target

    def read(self, relpath: str) -> str:
        return (self.repo / relpath).read_text()

    def write(self, relpath: str, content: str) -> None:
        (self.repo / relpath).write_text(content)

    def git(self, *args: str, author: tuple[str, str] | None = None
            ) -> subprocess.CompletedProcess:
        cmd = ["git", "-C", str(self.repo)]
        if author:
            cmd += ["-c", f"user.name={author[0]}", "-c", f"user.email={author[1]}"]
        return run(cmd + list(args))

    def commit(self, msg: str, *, author: tuple[str, str] | None = None) -> None:
        # Der Angreifer besitzt keinen Signaturschlüssel. Eine globale
        # Signatur-Einstellung des Rechners darf den Angriff nicht verfälschen.
        self.git("-c", "commit.gpgsign=false", "commit", "-am", msg, author=author)

    def push(self, branch: str | None = None) -> None:
        """Push nach <branch> (Default: Varianten-Branch). Ein abgelehnter Push
        (z. B. Signaturzwang der gehärteten Kette) gilt als geblockt."""
        branch = branch or self.cfg["branch"]
        try:
            self.git("push", "origin", f"HEAD:{branch}")
        except CommandError as exc:
            raise AttackBlocked(f"Push abgelehnt: {remote_reason(exc)}") from exc

    def head_sha(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    def remote_sha(self) -> str:
        """Aktueller Commit des Varianten-Branches im VCS."""
        out = run(["git", "ls-remote", self.push_url(), f"refs/heads/{self.cfg['branch']}"]).stdout
        return out.split()[0] if out.strip() else ""
    
    def deployed_image(self) -> str:
        """Liefert die Image-Referenz aus der aktuellen Deployment-Spec."""
        return run(kubectl(
            self.cfg, "get", "deployment", self.cfg["deployment"],
            "-n", self.cfg["deploy_ns"],
            "-o", "jsonpath={.spec.template.spec.containers[0].image}",
        )).stdout.strip()


    def reset_remote(self, sha: str) -> None:
        """Setzt den Varianten-Branch im VCS per Force-Push auf sha zurück.
        Es entsteht kein neuer Commit. Die Prüfung im VCS lässt das daher zu."""
        self.git("push", "--force", "origin", f"{sha}:refs/heads/{self.cfg['branch']}")

    # ---- Kette / Probe ---------------------------------------------------- #
    def _run_pipeline(self, run_file: str, timeout: str) -> tuple[bool, str]:
        """Startet einen PipelineRun und wartet auf Abschluss. (ok, name).
        Ein Fehlschlag wird sofort erkannt und nicht erst nach dem Timeout."""
        # Build-Auftrag der verifizierbaren Kette (AN2a): aktueller Stand des Branches im VCS
        manifest = (self.repo_root / run_file).read_text()
        if "__REVISION__" in manifest:
            manifest = manifest.replace("__REVISION__", self.remote_sha())
        # Deploy-Auftrag der verifizierbaren Kette (AN6): Image über den Digest
        if "__IMAGE__" in manifest:
            manifest = manifest.replace("__IMAGE__", self._image)
        name = run(
            kubectl(self.cfg, "create", "-f", "-", "-o", "jsonpath={.metadata.name}"),
            input=manifest,
        ).stdout.strip()
        deadline = time.time() + int(timeout.rstrip("s"))
        while time.time() < deadline:
            status = run(
                kubectl(self.cfg, "get", "pipelinerun", name,
                        "-o", "jsonpath={.status.conditions[0].status}"),
                check=False,
            ).stdout.strip()
            if status in ("True", "False"):
                return status == "True", name
            time.sleep(5)
        return False, name

    def _chain(self, *, fatal: bool) -> None:
        """Distribute- dann Deploy-Pipeline starten, dann Rollout abwarten.

        fatal=True: eine fehlgeschlagene Pipeline wirft AttackBlocked (Angriff).
        fatal=False: Fehler werden nur gemeldet (Cleanup-Neubau).
        """
        c = self.cfg
        for label, run_file, timeout in (
            ("Distribute", c["distribute_run"], "600s"),
            ("Deploy", c["deploy_run"], "300s"),
        ):
            ok, name = self._run_pipeline(run_file, timeout)
            print(f"    -> {label}-PipelineRun {name} ({'ok' if ok else 'FEHLER'})")
            if not ok:
                if fatal:
                    raise AttackBlocked(f"{label}-Pipeline nicht erfolgreich ({name})")
                print(f"    ! {label}-Pipeline nicht erfolgreich — Cleanup fährt fort")
                return
            if label == "Distribute" and c.get("image_repo"):
                self._image = f"{c['image_repo']}@{self._built_digest(name)}"
                print(f"    -> gebautes Image {self._image.split('@')[1][:19]}")
        rollout = run(
            kubectl(c, "rollout", "status", f"deployment/{c['deployment']}",
                    "-n", c["deploy_ns"], "--timeout=180s"),
            check=False,
        )
        if rollout.returncode != 0:
            reason = self._failed_create()
            if fatal:
                raise AttackBlocked(f"Rollout nicht abgeschlossen: {reason}")
            print(f"    ! Rollout nicht abgeschlossen: {reason}")

    def _built_digest(self, pipelinerun: str) -> str:
        """Digest des Images aus dem Result IMAGE_DIGEST des Build-Tasks."""
        return run(kubectl(
            self.cfg, "get", "taskrun",
            "-l", f"tekton.dev/pipelineRun={pipelinerun},tekton.dev/pipelineTask=build-and-push",
            "-o", "jsonpath={.items[0].status.results[?(@.name=='IMAGE_DIGEST')].value}",
        )).stdout.strip()

    def _failed_create(self) -> str:
        """Letzte Meldung zu nicht angelegten Pods (z. B. Ablehnung durch die Zulassungskontrolle)."""
        out = run(kubectl(
            self.cfg, "get", "events", "-n", self.cfg["deploy_ns"],
            "--field-selector", "reason=FailedCreate", "--sort-by=.lastTimestamp",
            "-o", "jsonpath={.items[-1:].message}",
        ), check=False).stdout.strip()
        return out[:300] or "keine Meldung"

    def run_chain(self) -> None:
        """Kette für den Angriff durchlaufen; blockt die Kette, -> AttackBlocked."""
        self._chain(fatal=True)

    def rebuild(self) -> None:
        """Kette im Cleanup neu bauen/deployen; Fehler werden nur gemeldet."""
        self._chain(fatal=False)

    @contextlib.contextmanager
    def deployed(self) -> Iterator[str]:
        """Öffnet `kubectl port-forward` auf das Deployment (im Namespace gibt es
        keinen Service) und liefert die Basis-URL, sobald /healthz antwortet."""
        c = self.cfg
        port = c["probe_port"]
        proc = subprocess.Popen(
            kubectl(c, "port-forward", "-n", c["deploy_ns"],
                    f"deployment/{c['deployment']}", f"{port}:{c['container_port']}"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            wait_http(f"http://127.0.0.1:{port}/healthz", timeout=30)
            yield f"http://127.0.0.1:{port}"
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    # ---- Aufräumen der temporären Klone (Runner ruft dies auf) ------------ #
    def _rmtmp(self) -> None:
        for tmp in self._tmpdirs:
            shutil.rmtree(tmp, ignore_errors=True)
        self._tmpdirs.clear()
