# Verifiable Software Supply Chains

Prototyp einer Software-Lieferkette. Eine Demo-Anwendung wird aus einem clusterinternen Git-Server (Gitea) gebaut, in eine clusterinterne Registry gepusht und im Cluster deployt. Alles läuft lokal in einem kind-Kubernetes-Cluster.

## Voraussetzungen

Folgende Tools müssen installiert sein:

- **Docker** (läuft im Hintergrund, wird von kind benötigt)
- **kind** – lokales Kubernetes in Docker
- **kubectl** – Kommandozeilenwerkzeug für Kubernetes
- **tkn** – Tekton CLI (für Pipeline-Logs, wird vom Makefile genutzt)
- **git** – um die Demo-App in Gitea zu pushen

Installation unter macOS:

```sh
brew install kind kubectl tektoncd-cli git
```

## Einmalige Einrichtung

1. **Cluster erstellen**

   ```sh
   kind create cluster --config cluster-config.yaml
   ```

2. **Tekton Pipelines installieren**

   ```sh
   kubectl apply -f https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml
   ```

3. **Gitea (VCS) und Registry deployen**

   ```sh
   kubectl apply -f Build/VCS/vcs.yaml
   kubectl apply -f Distribute/registry.yaml
   ```

4. **Demo-App nach Gitea pushen**

   Gitea ist unter <http://localhost:3000> erreichbar (Zugangsdaten: siehe `Build/VCS/readme.md`). Dort ein Repo `demo-app` anlegen und den Inhalt von `Produce/demo-app/` dorthin pushen.

5. **Pipelines und Tasks anlegen**

   ```sh
   kubectl apply -f Build/tasks/ -f Build/pipeline.yaml
   kubectl apply -f Distribute/pipeline.yaml
   kubectl apply -f Deploy/tasks/ -f Deploy/pipeline.yaml -f Deploy/deploy.yaml
   ```

## Benutzung

Build starten (Clone → Build → Push in die Registry):

```sh
make build
```

## Struktur

- `Produce/` – Quellcode der Demo-Anwendung
- `Build/` – Build-Pipeline (git-clone + Kaniko) und Gitea
- `Distribute/` – clusterinterne OCI-Registry und Distribute-Pipeline
- `Deploy/` – Deployment der Demo-App und Deploy-Pipeline
- `cluster-config.yaml` – kind-Cluster-Konfiguration