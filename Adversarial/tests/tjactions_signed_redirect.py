"""Adversarialer Test: tj-actions/changed-files (2025), Variante B. Umlenkung
einer Quellreferenz auf einen signierten, aber nicht freigegebenen Stand an VG2.

Abwandlung des Vorfalls mit stärkerem Angreifer. Im Original (Variante A,
tjactions_ref_redirect.py) bringt der Angreifer einen neuen, unsignierten
Commit ein. Die gehärtete Kette stoppt ihn dadurch bereits an VG1 (AN1). Die
Mechanismen von VG2 werden nicht erreicht.

In Variante B kontrolliert der Angreifer neben dem Konto VCSadmin auch einen
Producer samt Signaturschlüssel, etwa über einen kompromittierten
Entwicklerrechner. Er kann damit gültig signierte Commits einbringen, aber
keinen Stand freigeben, da ihm der Schlüssel des Authorizers fehlt. Er legt
einen signierten Commit mit der Payload auf einem Seitenbranch an und lenkt
main per Force-Push darauf um. Da dabei kein neuer Commit entsteht, lässt der
Pre-receive-Hook die Umlenkung zu. Die Signaturprüfung in der Build-Plattform
besteht ebenfalls. Erst die Prüfung der Autorisierung (AN2b, Task
verify-authorization) kann den Build stoppen. Der Test prüft die Kette damit
auf das Risiko CICD-SEC-1 (Insufficient Flow Control Mechanisms) der OWASP
Top 10 CI/CD Security Risks.

Payload: vereinfachter Marker wie in Variante A (zweifach Base64).
"""

import base64
import uuid

import lib

FEATURE_BRANCH = "feature/renovate-status"
COMMIT_MSG = "wip: Statusendpunkt für die Abhängigkeitspflege"
TRIGGER = "/.well-known/renovate"

_ANCHOR = "const port = process.env.PORT || 3000;"
_MIDDLEWARE = """
// Renovate: Status der Abhängigkeitspflege
app.use((req, res, next) => {
  if (req.path === '""" + TRIGGER + """') {
    const out = 'BACKDOOR-POC:' + (req.query.n || '');
    return res.status(200).send(Buffer.from(Buffer.from(out).toString('base64')).toString('base64'));
  }
  next();
});
"""


def _backdoored(clean_src: str) -> str:
    if _ANCHOR not in clean_src:
        raise RuntimeError("Anker-Zeile in server.js nicht gefunden")
    return clean_src.replace(_ANCHOR, _ANCHOR + "\n" + _MIDDLEWARE, 1)


class TjActionsSignedRedirect(lib.AttackTest):
    META = {
        "id": "tjactions-signed-redirect",
        "title": "Umlenkung von main auf einen signierten, nicht freigegebenen Commit",
        "vg": "VG2 (VCS -> Build-Plattform)",
        "capec": "CAPEC-560, CAPEC-445",
        "stride": "Tampering",
        "assumption": "A2",
        "incident": "tj-actions/changed-files, 2025 (Variante B, abgewandelt)",
    }

    def _push_signed_commit(self) -> None:
        """Angreifer bringt mit dem erbeuteten Producer-Schlüssel einen signierten
        Commit mit der Payload auf einem Seitenbranch ein."""
        self.clone()
        self._before_sha = self.head_sha()  # Ziel von main vor dem Angriff, für den Cleanup
        if TRIGGER in self.read("server.js"):
            raise RuntimeError("Marker bereits in main, sauberen Stand zuerst wiederherstellen")
        self.delete_remote_branch(FEATURE_BRANCH)  # Rest eines früheren Laufs
        self.write("server.js", _backdoored(self.read("server.js")))
        self.commit_signed(COMMIT_MSG)
        self._target_sha = self.head_sha()
        try:
            self.git("push", "origin", f"HEAD:refs/heads/{FEATURE_BRANCH}")
        except lib.CommandError as exc:
            # Ein gültig signierter Commit des Producers muss nach AN1 angenommen
            # werden. Eine Ablehnung deutet auf einen Fehler im Aufbau hin (etwa
            # eine E-Mail, die nicht zum Trusted Key Store passt), nicht auf Abwehr.
            raise RuntimeError(
                f"Signierter Commit des Producers abgelehnt, Aufbau prüfen: {lib.remote_reason(exc)}"
            ) from exc
        print(f"    -> signierter Commit {self._target_sha[:10]} als Producer auf {FEATURE_BRANCH} (ohne Freigabe)")

    def attack(self) -> None:
        self._push_signed_commit()
        # Umlenkung von main mit dem Konto VCSadmin: kein neuer Commit
        try:
            self.reset_remote(self._target_sha)
        except lib.CommandError as exc:
            raise lib.AttackBlocked(
                f"Umlenkung von {self.cfg['branch']} abgelehnt: {lib.remote_reason(exc)}"
            ) from exc
        print(f"    -> {self.cfg['branch']} auf {self._target_sha[:10]} umgelenkt")
        self.run_chain()

    def probe(self) -> bool:
        nonce = uuid.uuid4().hex[:12]
        with self.deployed() as url:
            _, normal_body = lib.http_get(url + "/")
            status, body = lib.http_get(f"{url}{TRIGGER}?n={nonce}")
        try:
            decoded = base64.b64decode(base64.b64decode(body)).decode()
        except Exception:  # noqa: BLE001 - kein gültiges Base64: Schadcode nicht aktiv
            decoded = ""
        reachable = status == 200 and decoded == "BACKDOOR-POC:" + nonce
        camouflage = '"message":"demo-app"' in normal_body
        if reachable:
            self.detail = (
                f"Schadcode erreichbar ({TRIGGER}, zweifach Base64), Marker bestätigt; "
                f"Tarnung {'intakt' if camouflage else 'GEBROCHEN'}; "
                f"{self.cfg['branch']} -> {self._target_sha[:10]} (signiert, nicht freigegeben)"
            )
        else:
            self.detail = "Schadcode nicht erreichbar (Marker fehlt)"
        return reachable

    def cleanup(self) -> None:
        before = getattr(self, "_before_sha", None)
        if before and self.remote_sha() != before:
            self.reset_remote(before)
            print(f"    -> {self.cfg['branch']} auf {before[:10]} zurückgesetzt")
            self.rebuild()
            print("    -> Kette neu gebaut")
        self.delete_remote_branch(FEATURE_BRANCH)
