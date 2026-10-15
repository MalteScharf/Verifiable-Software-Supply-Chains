# Ergebnisse: Tests des Herkunftsnachweises (AN4)

Ausgeführt am 2026-10-14 15:52

| Nr. | Fall | Erwartet | Ergebnis | Meldung des Verifiers | Bewertung |
|---|---|---|---|---|---|
| 1 | Normaler Build | zugelassen | zugelassen | alle drei Schritte ok | erwartet |
| 2 | Image an der Pipeline vorbei veröffentlicht (T4) | Schritt 1 | Schritt 1 | kein gültig signierter Herkunftsnachweis der Build-Plattform (cosign: no matching attestations: ) | erwartet |
| 3 | Gefälschter Nachweis mit eigenem Schlüssel | Schritt 1 | Schritt 1 | kein gültig signierter Herkunftsnachweis der Build-Plattform (cosign: no matching attestations: accepted signatures do not match threshold, Found: 0, Expected 1) | erwartet |
| 4 | Echter Nachweis an fremdes Image kopiert | Schritt 1 | Schritt 1 | kein gültig signierter Herkunftsnachweis der Build-Plattform (cosign: no matching attestations: no matching subject digest found) | erwartet |
| 5 | Nachweis aus älterer Pipeline ohne Freigabe | Schritt 2 | Schritt 2 | kein Autorisierungsnachweis im Herkunftsnachweis | erwartet |
| 6 | Manipulierter Task im Build (exit 0) | Schritt 3 | Schritt 3 | Build-Definition weicht von der Referenzliste ab | erwartet |
| 7 | Schlüsseltrennung (Pipeline, Gitea) | kein Zugriff | kein Zugriff | Pipeline und Gitea dürfen Secrets in tekton-chains weder lesen noch auflisten | erwartet |
| 8 | Wiederherstellung und erneuter Build | zugelassen | zugelassen | alle drei Schritte ok | erwartet |

Abweichungen: 0
