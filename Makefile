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

# Startet einen PipelineRun im angegebenen Kontext, zeigt die Logs und meldet das Ergebnis.
# $(1) = kubectl-Kontext, $(2) = PipelineRun-Datei
define run_pipeline
	@RUN=$$(kubectl --context $(1) create -f $(2) -o jsonpath='{.metadata.name}'); \
	echo "PipelineRun $$RUN gestartet"; \
	tkn --context $(1) pipelinerun logs -f $$RUN; \
	STATUS=$$(kubectl --context $(1) get pipelinerun $$RUN \
		-o jsonpath='{.status.conditions[0].status}'); \
	if [ "$$STATUS" = True ]; then echo "PipelineRun $$RUN erfolgreich"; \
	else echo "PipelineRun $$RUN fehlgeschlagen"; exit 1; fi
endef

.PHONY: conventional-build conventional-deploy \
        verified-cluster verified-base verified-build verified-deploy verified-check-trust verified-hook verified-hook-off

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
	@$(MAKE) --no-print-directory verified-hook

verified-hook:        ## Pre-receive-Hook (AN1) im Repository demo-app aktivieren
	kubectl --context $(VER_CTX) exec -n gitea deploy/gitea -- su git -c \
		"ln -sf /etc/vcs-hooks/verify-signatures.sh \
		/data/git/repositories/vcsadmin/$(GITEA_REPO).git/hooks/pre-receive.d/verify-signatures"

verified-hook-off:    ## Pre-receive-Hook abschalten (nur für Tests der Build-Prüfung)
	kubectl --context $(VER_CTX) exec -n gitea deploy/gitea -- su git -c \
		"rm -f /data/git/repositories/vcsadmin/$(GITEA_REPO).git/hooks/pre-receive.d/verify-signatures"

verified-build:       ## Distribute-Pipeline im Cluster der verifizierbaren Kette
	$(call run_pipeline,$(VER_CTX),$(DISTRIBUTE_RUN))

verified-deploy:      ## Deploy-Pipeline im Cluster der verifizierbaren Kette
	$(call run_pipeline,$(VER_CTX),$(DEPLOY_RUN))

# Trusted Key Store: eine ConfigMap im Namespace trust, gelesen von diesen Prüfern
TRUST_FILE    := Verified/Trust/allowed_signers_producer
TRUST_READERS := system:serviceaccount:gitea:default system:serviceaccount:default:default

verified-check-trust: ## Prüft Inhalt, Lese- (TK3) und Schreibrechte (TK2) des Trusted Key Store
	@fail=0; \
	want=$$(shasum -a 256 < $(TRUST_FILE) | cut -d' ' -f1); \
	have=$$(kubectl --context $(VER_CTX) -n trust get configmap trusted-key-store \
		-o jsonpath='{.data.allowed_signers_producer}' | shasum -a 256 | cut -d' ' -f1); \
	if [ "$$have" = "$$want" ]; then echo "Inhalt: identisch mit $(TRUST_FILE)"; \
	else echo "Inhalt: ABWEICHEND"; fail=1; fi; \
	for sa in $(TRUST_READERS); do \
		echo "$$sa"; \
		for verb in get update patch delete; do \
			r=$$(kubectl --context $(VER_CTX) auth can-i $$verb configmap/trusted-key-store \
				-n trust --as=$$sa 2>/dev/null); \
			if [ $$verb = get ]; then soll=yes; else soll=no; fi; \
			echo "  $$verb: $$r (Soll: $$soll)"; \
			[ "$$r" = "$$soll" ] || fail=1; \
		done; \
	done; \
	if [ $$fail -eq 0 ]; then echo "ok"; else echo "FEHLER"; exit 1; fi
