"""Adversarialer Test: PHP-Vorfall (git.php.net, 2021) — Konto-Übernahme an VG1.

Bildet den PHP-Vorfall auf den Prototyp ab: Ein Angreifer mit erlangten
Gitea-Zugangsdaten (CAPEC-560) pusht unter der Identität des legitimen
Committers einen als Tippfehler-Korrektur getarnten Backdoor-Commit. Die
Baseline prüft an VG1 (Producer -> VCS) weder Signatur noch Autorschaft, sodass
der Commit Build -> Distribute -> Deploy ungeprüft durchläuft (A1 verletzt).

Payload: vereinfachter Marker, kein Kommando-Exec. Trigger 1:1 wie im echten
Vorfall (Header `User-Agentt` mit doppeltem "t", Präfix `zerodium`, `slice(8)`).
"""

import uuid

import lib

# Gefälschte, aber legitim wirkende Autor-Identität. Entspricht dem
# Baseline-Committer der Demo-App; die Autorschaft ist durch das kompromittierte
# Konto gedeckt, nicht kryptographisch gebunden — genau die A1-Lücke.
FORGE = ("Malte Scharf", "malte.scharf@studium.fernuni-hagen.de")
COMMIT_MSG = "Fix typo in User-Agent header handling"

# Als Tippfehler-Korrektur getarnte Middleware. Ohne Trigger-Header ruft sie
# next() -> reguläres Verhalten (Tarnung).
_ANCHOR = "const port = process.env.PORT || 3000;"
_MIDDLEWARE = """
// Fix typo: korrigiere Namen des User-Agent-Headers beim Lookup
app.use((req, res, next) => {
  const ua = req.headers['user-agentt'];
  if (ua && ua.startsWith('zerodium')) {
    return res.status(200).send('BACKDOOR-POC:' + ua.slice(8));
  }
  next();
});
"""


def _backdoored(clean_src: str) -> str:
    if _ANCHOR not in clean_src:
        raise RuntimeError("Anker-Zeile in server.js nicht gefunden")
    return clean_src.replace(_ANCHOR, _ANCHOR + "\n" + _MIDDLEWARE, 1)


class PhpAccountTakeover(lib.AttackTest):
    META = {
        "id": "php-account-takeover",
        "title": "PHP git.php.net — Konto-Übernahme",
        "vg": "VG1 (Producer -> VCS)",
        "capec": "CAPEC-560",
        "stride": "Spoofing",
        "assumption": "A1",
        "incident": "PHP git.php.net, 2021",
    }

    def attack(self) -> None:
        self.clone(depth=1)
        if "user-agentt" in self.read("server.js"):
            self.detail = "Backdoor bereits in main — Commit übersprungen, Kette neu gebaut"
            print("    -> Backdoor bereits vorhanden, Commit übersprungen")
        else:
            self._before_sha = self.head_sha()  # Stand vor dem Angriff, für den Cleanup
            self.write("server.js", _backdoored(self.read("server.js")))
            self.commit(COMMIT_MSG, author=FORGE)
            print(f"    -> Backdoor-Commit als '{FORGE[0]}' erstellt")
            # Push über den kompromittierten HTTP-Basic-Auth-Pfad (keine Signaturprüfung).
            self.push()
            print("    -> Push über kompromittiertes VCSadmin-Konto akzeptiert")
        self._attack_sha = self.head_sha()
        self.run_chain()

    def probe(self) -> bool:
        nonce = uuid.uuid4().hex[:12] # zufälliger Marker, der im Response-Body auftauchen muss, wenn die Backdoor ausgelöst wird
        with self.deployed() as url:
            _, normal_body = lib.http_get(url + "/") 
            _, attack_body = lib.http_get(url + "/", headers={"User-Agentt": "zerodium" + nonce})

        reachable = ("BACKDOOR-POC:" + nonce) in attack_body
        camouflage = '"message":"demo-app"' in normal_body and nonce not in normal_body
        sha = getattr(self, "_attack_sha", "?")[:10]

        if reachable:
            self.detail = (
                f"Backdoor erreichbar (Header User-Agentt), Marker bestätigt; "
                f"Tarnung {'intakt' if camouflage else 'GEBROCHEN'}; "
                f"Commit {sha} als {FORGE[0]}"
            )
        else:
            self.detail = "Backdoor nicht erreichbar (Marker fehlt)"
        return reachable

    def cleanup(self) -> None:
        before = getattr(self, "_before_sha", None)
        if before:
            if self.remote_sha() == before:
                return  # Angriff wurde vor dem VCS gestoppt, nichts zurückzunehmen
            # Stand vor dem Angriff wiederherstellen. Ein Force-Push erzeugt keinen
            # neuen Commit und funktioniert daher auch mit der Prüfung im VCS.
            self.reset_remote(before)
            self.rebuild()
            print("    -> VCS auf Stand vor dem Angriff zurückgesetzt, Kette neu gebaut")
            return
        # Fallback: Die Backdoor war schon vor diesem Lauf in main.
        self.clone()
        if "user-agentt" not in self.read("server.js"):
            return  # nichts zurückzunehmen
        # Sauberen Stand aus der Entwickler-Arbeitskopie wiederherstellen.
        pristine = (self.repo_root / "Conventional" / "Produce" / "demo-app" / "server.js").read_text()
        self.write("server.js", pristine)
        self.commit("Revert: remove backdoor", author=FORGE)
        self.push()
        self.rebuild()
        print("    -> Backdoor zurückgenommen, Kette neu gebaut")
