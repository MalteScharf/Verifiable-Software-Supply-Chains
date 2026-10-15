# Gemeinsame Einstellungen für beide Ausbaustufen

# kubectl-Kontexte der beiden kind-Cluster
CONV_CTX := kind-software-supply-chain
VER_CTX  := kind-software-supply-chain-verified

# Tekton Pipelines mit fester Version, damit die Umgebung reproduzierbar bleibt (K1)
TEKTON_PIPELINES_VERSION := v1.6.0
TEKTON_RELEASE := https://infra.tekton.dev/tekton-releases/pipeline/previous/$(TEKTON_PIPELINES_VERSION)/release.yaml

# Gitea der verifizierbaren Kette (Zugangsdaten wie in Conventional/Build/VCS/readme.md)
VER_GITEA_URL := http://localhost:3001
GITEA_USER    := VCSadmin
GITEA_PASS    := VCSadmin
GITEA_EMAIL   := vcsadmin@example.com
GITEA_REPO    := demo-app

# Deploy-Pipeline, von beiden Ausbaustufen genutzt
DEPLOY_RUN := Conventional/Deploy/runs/run.yaml

# Lokale Demo-App der verifizierbaren Kette und zu bauender Commit (AN2a).
# Standard: aktueller Commit, überschreibbar mit z. B. make verified-build REV=<hash>
DEMO_DIR := Verified/Produce/demo-app
REV ?= $(shell git -C $(DEMO_DIR) rev-parse HEAD 2>/dev/null)

# Startet einen PipelineRun im angegebenen Kontext, zeigt die Logs und meldet das Ergebnis.
# $(1) = kubectl-Kontext, $(2) = PipelineRun-Datei (ein Platzhalter __REVISION__ wird durch REV ersetzt)
define run_pipeline
	@RUN=$$(sed 's/__REVISION__/$(REV)/' $(2) | kubectl --context $(1) create -f - -o jsonpath='{.metadata.name}'); \
	[ -n "$$RUN" ] || { echo "PipelineRun konnte nicht gestartet werden"; exit 1; }; \
	echo "PipelineRun $$RUN gestartet"; \
	tkn --context $(1) pipelinerun logs -f $$RUN; \
	STATUS=$$(kubectl --context $(1) get pipelinerun $$RUN \
		-o jsonpath='{.status.conditions[0].status}'); \
	if [ "$$STATUS" = True ]; then echo "PipelineRun $$RUN erfolgreich"; \
	else echo "PipelineRun $$RUN fehlgeschlagen"; exit 1; fi
endef
