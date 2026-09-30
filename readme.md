# Verifiable Software Supply Chains

Prototyp einer Software-Lieferkette in Kubernetes in zwei Ausbaustufen. Jede Stufe
läuft in einem eigenen lokalen kind-Cluster.

## Struktur

- `Conventional/` – konventionelle Lieferkette (Baseline): Demo-Anwendung, Gitea,
  Build-, Distribute- und Deploy-Pipeline. Einrichtung siehe `Conventional/readme.md`.
- `Verified/` – Erweiterungen der verifizierbaren Lieferkette. Sie baut auf den
  Dateien in `Conventional/` auf und ergänzt diese.
- `Adversarial/` – adversariale Tests, die dokumentierte Angriffe gegen beide
  Ausbaustufen ausführen. Siehe `Adversarial/README.md`.
- `Makefile` – Befehle für beide Ausbaustufen.

Alle Befehle in den READMEs werden im Hauptordner des Repos ausgeführt.
