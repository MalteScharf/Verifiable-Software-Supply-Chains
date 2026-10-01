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

## Unterschiede zur konventionellen Kette

| Datei | Änderung |
|---|---|
| `cluster-config.yaml` | eigener Clustername, Gitea auf Host-Port 3001 |
| `VCS/root-url.yaml` | ROOT_URL von Gitea auf Port 3001 |
| `Trust/` | Trusted Key Store (AN1): Schlüssel in `allowed_signers_producer`, `kustomization.yaml` erzeugt daraus die ConfigMap `trusted-key-store` in den Namespaces `gitea` und `default` |
