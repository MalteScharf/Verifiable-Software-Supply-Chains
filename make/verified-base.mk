# Verifizierbare Lieferkette: Cluster, Grundinstallation und Prüfung im VCS (AN1)

##@ Verifizierbare Lieferkette: Einrichtung
.PHONY: verified-cluster verified-base verified-hook verified-hook-off

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
	@# Testaufbau T3: Die .npmrc der Demo-App zeigt auf den npm-Index, ohne ihn scheitert der Build
	@$(MAKE) --no-print-directory npm-index-verified

verified-hook:        ## Pre-receive-Hook (AN1) im Repository demo-app aktivieren
	kubectl --context $(VER_CTX) exec -n gitea deploy/gitea -- su git -c \
		"ln -sf /etc/vcs-hooks/verify-signatures.sh \
		/data/git/repositories/vcsadmin/$(GITEA_REPO).git/hooks/pre-receive.d/verify-signatures"

verified-hook-off:    ## Pre-receive-Hook abschalten (nur für Tests der Build-Prüfung)
	kubectl --context $(VER_CTX) exec -n gitea deploy/gitea -- su git -c \
		"rm -f /data/git/repositories/vcsadmin/$(GITEA_REPO).git/hooks/pre-receive.d/verify-signatures"
