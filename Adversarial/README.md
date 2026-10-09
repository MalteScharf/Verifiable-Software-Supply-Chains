# Adversariale Tests

Reproduzieren dokumentierte Lieferkettenangriffe gegen den Prototyp und
belegen, welche Vertrauensgrenze verletzt wird. Ein schlanker Python-Runner
findet alle Tests im Ordner `tests/` und führt sie gegen beide Ausbaustufen aus:
die **Baseline** (konventionell, ungehärtet) und die **gehärtete** Kette
(verifizierbare Lieferkette in `Verified/`). Jede Variante läuft in einem eigenen
kind-Cluster und wird über ihren festen kubectl-Kontext angesprochen.

Es gibt bewusst **keine** Soll-/Ist-Bewertung. Der Runner führt den Angriff aus
und berichtet, was passiert ist. Die Auswertung liest ab: Baseline `vulnerable`,
gehärtet (später) `blocked`.

## Ausführen

Voraussetzung: laufendes Baseline-Setup gemäß `Conventional/readme.md` (kind-Cluster,
Tekton, Gitea + Registry deployt, Demo-App in Gitea gepusht, Pipelines/Tasks und
`Conventional/Deploy/deploy.yaml` appliziert). Werkzeuge: `python3`, `git`, `kubectl`, `tkn`.

```sh
python3 Adversarial/runner.py                    # alle Tests, beide Varianten
python3 Adversarial/runner.py --variant baseline # nur Baseline
python3 Adversarial/runner.py --test php-account-takeover
python3 Adversarial/runner.py --keep             # Cleanup auslassen (Debug)
```

Am Ende steht eine Ergebnistabelle auf der Konsole und in `Adversarial/results.md`.

### Outcomes

| Outcome | Bedeutung |
|---|---|
| `vulnerable` | Angriff durchgelaufen, Backdoor im Deployment erreichbar |
| `blocked` | Angriffsaktion verhindert (Push/Pipeline) oder Backdoor nicht erreichbar |
| `skipped` | Variante nicht erreichbar bzw. noch nicht implementiert |
| `error` | unerwarteter Fehler in Harness oder Test |

## Aufbau

- `runner.py` — Discovery, Varianten-Loop, Ergebnistabelle
- `lib.py` — Varianten-Configs (`baseline`, `hardened`) und Helfer
  (Subprozess, `port_forward`, HTTP-Probe, Erreichbarkeitsprüfung)
- `tests/<name>.py` — je ein Test

Der Runner provisioniert die Ketten **nicht**; er zielt auf die jeweils bereits
deployte Kette und meldet eine nicht erreichbare Variante als `skipped`.

## Einen Test schreiben

Ein Test ist eine Datei in `tests/` mit einer Unterklasse von `lib.AttackTest`,
die ein `META`-Dict und die drei Methoden `attack` / `probe` / `cleanup`
mitbringt:

```python
import lib

class MeinAngriff(lib.AttackTest):
    META = {"id": "...", "title": "...", "vg": "...", "capec": "...",
            "stride": "...", "assumption": "...", "incident": "..."}

    def attack(self):        # bösartige Aktion.
                             # Erkennt der Test, dass die Kette blockt: lib.AttackBlocked werfen.
    def probe(self) -> bool: # True = Angriff erfolgreich (Backdoor erreichbar)
    def cleanup(self):       # sauberen Zustand wiederherstellen (läuft immer, außer --keep)
```

Die Basisklasse liefert die wiederverwendbaren Bausteine, sodass ein Test kurz
bleibt:

- `self.clone(depth=...)` — Repo in einen temporären Klon holen (setzt `self.repo`)
- `self.read(pfad)` / `self.write(pfad, inhalt)` — Datei im Klon lesen/schreiben
- `self.commit(msg, author=(name, email))` / `self.push(branch=None)` —
  ein abgelehnter Push wirft automatisch `AttackBlocked`
- `self.run_chain()` — Distribute + Deploy + Rollout; blockt die Kette, wirft `AttackBlocked`
- `self.rebuild()` — wie `run_chain`, aber für Cleanup (Fehler nur gemeldet)
- `with self.deployed() as url:` — port-forward auf das Deployment, liefert die Basis-URL
- Ergebnismeldung in `self.detail` ablegen; Zwischenstände als eigene Attribute
  (z. B. `self._attack_sha`)

`self.variant`, `self.cfg` (Varianten-Config) und `self.repo_root` stehen bereit.
Die Angriffsaktion ist variantenunabhängig; alle Endpunkte (Namespace, Gitea-URL,
Ports, PipelineRun-Dateien) kommen aus `self.cfg`, damit derselbe Test ohne
Änderung gegen Baseline und gehärtete Kette läuft. Temporäre Klone räumt der
Runner auf.

## Gehärtete Variante

Konfiguriert in `lib.py` unter `VARIANTS["hardened"]` (Gitea auf Port 3001,
Kontext `kind-software-supply-chain-verified`). Erwartet wird `blocked`.

Um zu zeigen, dass die Build-Plattform einen Angriff auch ohne die Prüfung im VCS
stoppt, den Pre-receive-Hook vorübergehend abschalten:

```sh
make verified-hook-off
python3 Adversarial/runner.py --variant hardened
make verified-hook
```

## Tests

- `php-account-takeover` — PHP-Vorfall (git.php.net, 2021), Konto-Übernahme an
  VG1 (Producer → VCS), CAPEC-560, verletzte Annahme A1. Pusht einen getarnten
  Backdoor-Commit über das kompromittierte `VCSadmin`-Konto; die Backdoor
  reagiert im deployten Pod auf den Header `User-Agentt: zerodium…` (vereinfachter
  Marker, kein Kommando-Exec). Baseline: `vulnerable`.
