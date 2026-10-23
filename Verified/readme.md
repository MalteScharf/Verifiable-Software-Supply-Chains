# Verifizierbare Lieferkette

Erweitert die konventionelle Lieferkette aus `../Conventional` und läuft in einem
eigenen kind-Cluster (`software-supply-chain-verified`). Grundlage sind die
unveränderten Manifeste aus `Conventional/`. Alle Änderungen stehen in
`kustomization.yaml`.

Alle Befehle werden im Hauptordner des Repos ausgeführt. Voraussetzungen wie in
`Conventional/readme.md`, zusätzlich `curl`, `jq`, `cosign` und `crane`.

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

5. **Signaturschlüssel des Authorizers (AN2b)**

   Zweiter Schlüssel, nur für Freigaben. Er steht in einer eigenen Datei des
   Trusted Key Store, getrennt von den Producer-Schlüsseln.

   ```sh
   ssh-keygen -t ed25519 -f ~/.ssh/authorizer_signing -C "authorizer signing"
   echo "authorizer@example.com namespaces=\"git\" $(cat ~/.ssh/authorizer_signing.pub)" >> Verified/Trust/allowed_signers_authorizer
   make verified-base
   make verified-check-trust
   ```

6. **Herkunftsnachweis mit Tekton Chains (AN4)**

   Installiert Tekton Chains, legt den Signaturschlüssel der Build-Plattform im
   Cluster an und übernimmt dessen öffentlichen Teil als `build_platform.pub` in den
   Trusted Key Store. Der private Schlüssel liegt nur im Cluster.

   ```sh
   make verified-chains
   make verified-base          # Pipeline mit Resolver und neuem Task-Result anwenden
   make verified-check-chains  # Pipeline und Gitea dürfen den Schlüssel nicht lesen
   make verified-check-trust
   ```

   Nach dem ersten erfolgreichen Build legt der Administrator die Referenzliste der
   Build-Definition fest. Nur nach bewussten Änderungen an Pipeline oder Tasks wiederholen.

   ```sh
   make verified-pin-build-definition
   ```

7. **Stückliste (AN5)**

   Holt die Meldeliste von OpenSSF, legt ihren Index in die Registry und seinen
   Digest als `malicious_packages` in den Trusted Key Store. Zum Aktualisieren erneut ausführen.

   ```sh
   make verified-malicious-packages
   ```

8. **Zulassungskontrolle (AN6, AN7)**

   Installiert Kyverno, macht die Registry unter ihrem Cluster-Namen auf den Knoten
   erreichbar, baut den Prüfdienst und wendet die Richtlinie an. Vorher die Basis-Images
   in `Verifier/Dockerfile` per Digest festlegen (`crane digest`).

   ```sh
   make verified-kyverno
   make verified-registry-alias
   make verified-pruefdienst
   make verified-admission-policy
   ```

## Benutzung

```sh
make verified-approve  # Freigabe: signierter Tag des Authorizers auf den aktuellen Commit
make verified-build    # Clone, Build, Push in die Registry
make verified-deploy   # Image über den Digest ausrollen (Standard: demo-app:latest, sonst DIGEST=...)
make verified-provenance  # Herkunftsnachweis des letzten Builds anzeigen
make verified-verify      # Herkunftsnachweis und Stückliste von demo-app:latest prüfen (AN4, AN5)
```

`make verified-build` baut den aktuellen Commit der lokalen Demo-App
(`Verified/Produce/demo-app`). Einen anderen Stand nennt man über seinen Commit-Hash:

```sh
make verified-approve REV=<commit-hash>
make verified-build REV=<commit-hash>
```

Gebaut wird nur ein Stand, für den ein vom Authorizer signierter Tag existiert.

## Unterschiede zur konventionellen Kette

| Datei | Änderung |
|---|---|
| `cluster-config.yaml` | eigener Clustername, Gitea auf Host-Port 3001 |
| `VCS/root-url.yaml` | ROOT_URL von Gitea auf Port 3001 |
| `Trust/` | Trusted Key Store (AN1, AN2b): Schlüssel in `allowed_signers_producer` und `allowed_signers_authorizer`, daraus die ConfigMap `trusted-key-store` im Namespace `trust`. `trust.yaml` legt fest, wer lesen darf (Gitea, Tekton). |
| `VCS/verify-signatures.sh`, `VCS/hook-mount.yaml` | Pre-receive-Hook (AN1): prüft beim Push jeden neuen Commit gegen den Trusted Key Store. Aktiviert durch `make verified-hook` (Teil von `verified-base`). |
| `Build/tasks/verify-signatures.yaml`, `Build/pipeline-patch.yaml` | Prüfung in der Build-Plattform (AN1): neuer Task nach `git-clone`, der alle Commits gegen den Trusted Key Store prüft. Der Patch fügt ihn in die Distribute-Pipeline ein. |
| `Build/tasks/verify-revision.yaml`, `Distribute/runs/run-gitea.yaml` | Quellreferenz (AN2a): Der Build-Auftrag nennt den Commit-Hash (Parameter `revision`). `git-clone` holt genau diesen Commit, `verify-revision` prüft ihn vor der Signaturprüfung. |
| `Build/tasks/verify-authorization.yaml` | Autorisierung (AN2b): prüft, ob ein Tag auf den Commit zeigt, den ein Authorizer aus dem Trusted Key Store signiert hat. Freigabe mit `make verified-approve`. |
| `Produce/demo-app/.npmrc` | Abhängigkeitsauflösung über den npm-Index (Testaufbau für T3, `Adversarial/npm-index.yaml`, wird von `make verified-base` angelegt): `npm ci` leitet mit `replace-registry-host=always` auch die Tarball-Anfragen über den Index, damit die Integritätsprüfung des Lockfiles gegen einen manipulierten Tarball derselben Version greift. |
| `Build/tasks/verify-dependencies.yaml` | Abhängigkeitsdefinition (AN3): prüft, dass `package-lock.json` für jedes Paket einen Hashwert enthält, jede `FROM`-Zeile einen Digest nennt und das Dockerfile mit `npm ci` installiert. Den Hashwert jedes Pakets prüft `npm ci` beim Build. |
| `Chains/chains-config.yaml` | Herkunftsnachweis (AN4): Konfiguration von Tekton Chains. Ein Nachweis pro Build im Format SLSA 1.0, Ablage in der Registry neben dem Image. |
| `Build/pipeline-resolver-patch.yaml`, `Distribute/runs/run-gitea.yaml` | Build-Definition (AN4): Pipeline und Tasks werden über den Cluster-Resolver geladen. Ihr Digest steht damit im Herkunftsnachweis. |
| `Build/tasks/verify-authorization.yaml` | Autorisierungsnachweis (AN4): gibt das signierte Tag-Objekt als Result `AUTHORIZATION_TAG` aus. Chains übernimmt es in den Herkunftsnachweis. |
| `Trust/build_platform.pub` | Öffentlicher Schlüssel der Build-Plattform im Trusted Key Store (AN4), erzeugt mit `make verified-chains`. |
| `Trust/build_definition` | Referenzliste der Build-Definition im Trusted Key Store (AN4): erwartete Digests von Pipeline und Tasks, festgelegt mit `make verified-pin-build-definition`. |
| `Verify/verify-provenance.sh` | Vorläufiger Verifier (AN4, AN5): prüft Herkunftsnachweis, Stückliste, Lockfile und Meldeliste. Aufruf über `make verified-verify`. |
| `Build/tasks/sbom.yaml`, `Build/pipeline-sbom-patch.yaml` | Stückliste (AN5): Syft erzeugt sie nach dem Build, cosign legt sie neben das Image, ihr Digest steht im Herkunftsnachweis. |
| `Trust/malicious_packages`, `Verify/malicious-*.jq` | Meldeliste (AN5b): Stand und Digest des Index im Trusted Key Store, Index und Abgleich mit jq. |
| `Admission/` | Zulassungskontrolle (AN6, AN7): Kyverno in fester Version und Richtlinie `verified-images` (Digest, Herkunftsnachweis, Build-Definition, Aufruf des Prüfdienstes). |
| `Verifier/` | Prüfdienst (AN7): prüft Freigabe, Stückliste, Lockfile und Meldeliste für Kyverno. |
| `Deploy/` | Deploy über den Digest (AN6): Deploy-Auftrag und Deployment nennen das Image über seinen Digest. |
