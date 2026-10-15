# Verifiable Software Supply Chains

Prototyp einer Software-Lieferkette in Kubernetes in zwei Ausbaustufen. Jede Stufe
läuft in einem eigenen lokalen kind-Cluster.

## Struktur

- `Conventional/` – konventionelle Lieferkette (Baseline): Demo-Anwendung, Gitea,
  Build-, Distribute- und Deploy-Pipeline. Einrichtung siehe `Conventional/readme.md`.
- `Verified/` – Erweiterungen der verifizierbaren Lieferkette. Sie baut auf den
  Dateien in `Conventional/` auf und ergänzt diese. Einrichtung siehe
  `Verified/readme.md`.
- `Adversarial/` – adversariale Tests, die dokumentierte Angriffe gegen beide
  Ausbaustufen ausführen. Siehe `Adversarial/README.md`.
- `Makefile` und `make/` – Befehle für beide Ausbaustufen, nach Ausbaustufe und
  Anforderung auf Teildateien verteilt. Übersicht aller Befehle mit `make help`.

Alle Befehle in den READMEs werden im Hauptordner des Repos ausgeführt.
