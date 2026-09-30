"""Gemeinsame Bausteine für die adversarialen Tests.

Enthält die Varianten-Konfigurationen (Baseline / gehärtet), kleine Helfer für
Subprozess-Aufrufe und HTTP-Probes sowie die Basisklasse `AttackTest`, von der
jeder Test erbt. Bewusst schlank: nur Python-Standardbibliothek, keine externen
Abhängigkeiten. Externe Werkzeuge (git, kubectl, tkn) werden per Subprozess
aufgerufen.
"""

from __future__ import annotations

import contextlib
import shutil
import subprocess
import tempfile
import time
import urllib.error
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


class AttackBlocked(Exception):
    """Die Lieferkette hat die Angriffsaktion verhindert.

    Ein Test wirft dies, wenn er erkennt, dass die Kette den Angriff gestoppt
    hat (z. B. Push abgelehnt oder Pipeline nicht erfolgreich). Für die Baseline
    ist das nicht zu erwarten; für die gehärtete Variante ist es das Ziel.
    """


# Varianten. Der Runner provisioniert nichts, er zielt auf die jeweils bereits
# deployte Kette. "hardened" ist noch nicht implementiert und wird übersprungen.
VARIANTS = {
    "baseline": {
        "status": "active",
        "gitea_host": "localhost:3000",
        "gitea_user": "VCSadmin",
        "gitea_password": "VCSadmin",
        "repo_path": "VCSadmin/demo-app.git",
        "branch": "main",
        "deploy_ns": "deploy",
        "deployment": "demo-app",
        "container_port": 3000,
        "probe_port": 18080,
        "distribute_run": "Distribute/runs/run-gitea.yaml",
        "deploy_run": "Deploy/runs/run.yaml",
    },
    "hardened": {
        # Platzhalter: die gehärtete Kette (Signaturzwang, Verify-Gate,
        # Admission-Policy) ist noch nicht gebaut. Endpunkte später ergänzen und
        # status auf "active" setzen.
        "status": "pending",
    },
}


# --------------------------------------------------------------------------- #
# Helfer
# --------------------------------------------------------------------------- #
def run(cmd: list[str], *, cwd=None, check: bool = True, timeout=None, env=None
        ) -> subprocess.CompletedProcess:
    """Führt ein Kommando aus und liefert das CompletedProcess-Ergebnis.

    Bei check=True und Fehlercode wird CommandError geworfen.
    """
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        env=env,
        timeout=timeout,
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
            ["kubectl", "get", "deployment", cfg["deployment"], "-n", cfg["deploy_ns"]],
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
        self.git("commit", "-am", msg, author=author)

    def push(self, branch: str | None = None) -> None:
        """Push nach <branch> (Default: Varianten-Branch). Ein abgelehnter Push
        (z. B. Signaturzwang der gehärteten Kette) gilt als geblockt."""
        branch = branch or self.cfg["branch"]
        try:
            self.git("push", "origin", f"HEAD:{branch}")
        except CommandError as exc:
            raise AttackBlocked(f"Push abgelehnt: {exc}") from exc

    def head_sha(self) -> str:
        return self.git("rev-parse", "HEAD").stdout.strip()

    # ---- Kette / Probe ---------------------------------------------------- #
    def _run_pipeline(self, run_file: str, timeout: str) -> tuple[bool, str]:
        """Startet einen PipelineRun und wartet auf Abschluss. (ok, name)."""
        path = str(self.repo_root / run_file)
        name = run(
            ["kubectl", "create", "-f", path, "-o", "jsonpath={.metadata.name}"]
        ).stdout.strip()
        res = run(
            ["kubectl", "wait", "--for=condition=Succeeded",
             f"pipelinerun/{name}", f"--timeout={timeout}"],
            check=False,
        )
        return res.returncode == 0, name

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
        run(
            ["kubectl", "rollout", "status", f"deployment/{c['deployment']}",
             "-n", c["deploy_ns"], "--timeout=180s"],
            check=False,
        )

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
            ["kubectl", "port-forward", "-n", c["deploy_ns"],
             f"deployment/{c['deployment']}", f"{port}:{c['container_port']}"],
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
