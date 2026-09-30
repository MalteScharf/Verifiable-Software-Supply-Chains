# Befehle für beide Ausbaustufen. Jeder Befehl nutzt einen festen kubectl-Kontext,
# damit er nie versehentlich im falschen Cluster läuft.

CONV_CTX := kind-software-supply-chain
VER_CTX  := kind-software-supply-chain-verified

TEKTON_RELEASE := https://storage.googleapis.com/tekton-releases/pipeline/latest/release.yaml

# Gitea der verifizierbaren Kette (Zugangsdaten wie in Conventional/Build/VCS/readme.md)
VER_GITEA_URL := http://localhost:3001
GITEA_USER    := VCSadmin
GITEA_PASS    := VCSadmin
GITEA_EMAIL   := vcsadmin@example.com
GITEA_REPO    := demo-app

DISTRIBUTE_RUN := Conventional/Distribute/runs/run-gitea.yaml
DEPLOY_RUN     := Conventional/Deploy/runs/run.yaml

# Startet einen PipelineRun im angegebenen Kontext, zeigt die Logs und wartet auf Erfolg.
# $(1) = kubectl-Kontext, $(2) = PipelineRun-Datei
define run_pipeline
	@RUN=$$(kubectl --context $(1) create -f $(2) -o jsonpath='{.metadata.name}'); \
	echo "PipelineRun $$RUN gestartet"; \
	tkn --context $(1) pipelinerun logs -f $$RUN; \
	kubectl --context $(1) wait --for=condition=Succeeded pipelinerun/$$RUN --timeout=10m
endef

.PHONY: conventional-build conventional-deploy \
        verified-cluster verified-base verified-build verified-deploy

# ---------------------------------------------------------------------------
# Konventionelle Lieferkette
# ---------------------------------------------------------------------------
conventional-build:   ## Distribute-Pipeline: Clone, Build, Push in die Registry
	$(call run_pipeline,$(CONV_CTX),$(DISTRIBUTE_RUN))

conventional-deploy:  ## Deploy-Pipeline: Rollout-Restart der Demo-App
	$(call run_pipeline,$(CONV_CTX),$(DEPLOY_RUN))

# ---------------------------------------------------------------------------
# Verifizierbare Lieferkette
# ---------------------------------------------------------------------------
verified-cluster:     ## kind-Cluster der verifizierbaren Kette anlegen
	kind create cluster --config Verified/cluster-config.yaml

verified-base:        ## Tekton, Gitea, Registry, Tasks, Pipelines, Deploy sowie Gitea-Benutzer und Repo
	kubectl --context $(VER_CTX) apply -f $(TEKTON_RELEASE)
	kubectl --context $(VER_CTX) wait --for=condition=Available deployment --all \
		-n tekton-pipelines --timeout=5m
	kubectl kustomize --load-restrictor=LoadRestrictionsNone Verified \
		| kubectl --context $(VER_CTX) apply -f -
	kubectl --context $(VER_CTX) rollout status deployment/gitea -n gitea --timeout=5m
	@echo "Gitea-Benutzer $(GITEA_USER) anlegen (falls noch nicht vorhanden)"
	@for i in $$(seq 1 20); do \
		if kubectl --context $(VER_CTX) exec -n gitea deploy/gitea -- \
			su git -c "gitea admin user list" 2>/dev/null | grep -q "$(GITEA_USER)"; then \
			echo "  bereits vorhanden"; break; fi; \
		if kubectl --context $(VER_CTX) exec -n gitea deploy/gitea -- \
			su git -c "gitea admin user create --admin --username $(GITEA_USER) \
			--password $(GITEA_PASS) --email $(GITEA_EMAIL) --must-change-password=false"; then \
			break; fi; \
		echo "  Gitea noch nicht bereit, neuer Versuch in 3s"; sleep 3; \
	done
	@echo "Repository $(GITEA_USER)/$(GITEA_REPO) anlegen (falls noch nicht vorhanden)"
	@for i in $$(seq 1 20); do \
		curl -sf -o /dev/null $(VER_GITEA_URL)/api/v1/version && break; \
		echo "  Gitea-API noch nicht erreichbar, neuer Versuch in 3s"; sleep 3; \
	done
	@CODE=$$(curl -s -o /dev/null -w "%{http_code}" -u $(GITEA_USER):$(GITEA_PASS) \
		-X POST -H "Content-Type: application/json" \
		-d '{"name":"$(GITEA_REPO)","private":false,"default_branch":"main"}' \
		$(VER_GITEA_URL)/api/v1/user/repos); \
	case $$CODE in \
		201) echo "  angelegt";; \
		409) echo "  bereits vorhanden";; \
		*) echo "  Fehler: HTTP $$CODE"; exit 1;; \
	esac

verified-build:       ## Distribute-Pipeline im Cluster der verifizierbaren Kette
	$(call run_pipeline,$(VER_CTX),$(DISTRIBUTE_RUN))

verified-deploy:      ## Deploy-Pipeline im Cluster der verifizierbaren Kette
	$(call run_pipeline,$(VER_CTX),$(DEPLOY_RUN))
