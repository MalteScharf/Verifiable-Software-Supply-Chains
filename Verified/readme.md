# Verifizierbare Lieferkette

Erweitert die konventionelle Lieferkette aus `../Conventional` und läuft in einem
eigenen kind-Cluster (`software-supply-chain-verified`). Grundlage sind die
unveränderten Manifeste aus `Conventional/`. Alle Änderungen stehen in
`kustomization.yaml`.

Alle Befehle werden im Hauptordner des Repos ausgeführt. Voraussetzungen wie in
`Conventional/readme.md`, zusätzlich `curl`.

## Einmalige Einrichtung

1. **Cluster erstellen**

   ```sh
   make verified-cluster
   ```

2. **Grundinstallation**

   Installiert Tekton, Gitea, Registry, Tasks, Pipelines und das Deployment der
   Demo-App. Legt außerdem in Gitea den Benutzer `VCSadmin` und das Repository
   `demo-app` an.

   ```sh
   make verified-base
   ```

   Gitea ist danach unter <http://localhost:3001> erreichbar
   (Zugangsdaten wie in `Conventional/Build/VCS/readme.md`).

3. **Demo-App pushen**

   ```sh
   git -C Conventional/Produce/demo-app remote add verified http://localhost:3001/VCSadmin/demo-app.git
   git -C Conventional/Produce/demo-app push verified main
   ```

4. **Signaturschlüssel des Producers und Trusted Key Store**

   Eigenen Schlüssel nur zum Signieren erzeugen. Den öffentlichen Teil **nicht**
   im Gitea-Konto hinterlegen.

   ```sh
   ssh-keygen -t ed25519 -f ~/.ssh/producer_signing -C "producer signing"
   echo "malte.scharf@studium.fernuni-hagen.de namespaces=\"git\" $(cat ~/.ssh/producer_signing.pub)" >> Verified/Trust/allowed_signers_producer
   git -C Conventional/Produce/demo-app config user.email malte.scharf@studium.fernuni-hagen.de
   ```

   Danach den Trusted Key Store in den Cluster übernehmen und prüfen:

   ```sh
   make verified-base
   make verified-check-trust
   ```

## Benutzung

```sh
make verified-build    # Clone, Build, Push in die Registry
make verified-deploy   # Deployment neu starten
```

`make verified-build` baut den aktuellen Commit der lokalen Demo-App
(`Verified/Produce/demo-app`). Einen anderen Stand nennt man über seinen Commit-Hash:

```sh
make verified-build REV=<commit-hash>
```

## Unterschiede zur konventionellen Kette

| Datei | Änderung |
|---|---|
| `cluster-config.yaml` | eigener Clustername, Gitea auf Host-Port 3001 |
| `VCS/root-url.yaml` | ROOT_URL von Gitea auf Port 3001 |
| `Trust/` | Trusted Key Store (AN1): Schlüssel in `allowed_signers_producer`, daraus die ConfigMap `trusted-key-store` im Namespace `trust`. `trust.yaml` legt fest, wer lesen darf (Gitea, Tekton). |
| `VCS/verify-signatures.sh`, `VCS/hook-mount.yaml` | Pre-receive-Hook (AN1): prüft beim Push jeden neuen Commit gegen den Trusted Key Store. Aktiviert durch `make verified-hook` (Teil von `verified-base`). |
| `Build/tasks/verify-signatures.yaml`, `Build/pipeline-patch.yaml` | Prüfung in der Build-Plattform (AN1): neuer Task nach `git-clone`, der alle Commits gegen den Trusted Key Store prüft. Der Patch fügt ihn in die Distribute-Pipeline ein. |
| `Build/tasks/verify-revision.yaml`, `Distribute/runs/run-gitea.yaml` | Quellreferenz (AN2a): Der Build-Auftrag nennt den Commit-Hash (Parameter `revision`). `git-clone` holt genau diesen Commit, `verify-revision` prüft ihn vor der Signaturprüfung. |
