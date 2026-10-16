# Verifizierbare Lieferkette: Build mit Prüfungen (AN1 bis AN3) und Deploy

# Build-Auftrag der verifizierbaren Kette (AN2a), nennt den Commit über __REVISION__
VER_DISTRIBUTE_RUN := Verified/Distribute/runs/run-gitea.yaml

##@ Verifizierbare Lieferkette: Build und Deploy
.PHONY: verified-build verified-deploy

verified-build:       ## Distribute-Pipeline im Cluster der verifizierbaren Kette (Commit über REV)
	$(call run_pipeline,$(VER_CTX),$(VER_DISTRIBUTE_RUN))

# Deploy-Auftrag und Deployment-Beschreibung nennen das Image über den Digest (AN6)
VER_DEPLOY_RUN := Verified/Deploy/runs/run-deploy.yaml
DEPLOY_PATCH   := Verified/Deploy/deployment-patch.yaml

verified-deploy:      ## Deploy-Pipeline: Image über den Digest setzen (Standard: demo-app:latest, sonst DIGEST=sha256:...)
	@D="$(DIGEST)"; \
	if [ -z "$$D" ]; then \
		kubectl --context $(VER_CTX) port-forward -n registry svc/registry $(VERIFY_PORT):5000 >/dev/null 2>&1 & PF=$$!; \
		for i in $$(seq 1 20); do curl -sf -o /dev/null http://localhost:$(VERIFY_PORT)/v2/ && break; sleep 0.5; done; \
		D=$$(curl -sfI -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
			-H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
			http://localhost:$(VERIFY_PORT)/v2/demo-app/manifests/latest \
			| awk 'tolower($$1)=="docker-content-digest:" {print $$2}' | tr -d '\r'); \
		{ kill $$PF; wait $$PF; } 2>/dev/null; \
	fi; \
	echo "$$D" | grep -Eqx 'sha256:[0-9a-f]{64}' || { echo "Kein gültiger Digest: $$D"; exit 1; }; \
	REF=$(REGISTRY_NAME)/demo-app@$$D; echo "Image: $$REF"; \
	printf '%s\n' "# Deployment-Beschreibung des Consumers (AN6): Image über den Digest." \
		"# Wird von make verified-deploy geschrieben." \
		"- {op: test, path: /spec/template/spec/containers/0/name, value: demo-app}" \
		"- op: replace" "  path: /spec/template/spec/containers/0/image" "  value: $$REF" > $(DEPLOY_PATCH); \
	RUN=$$(sed "s|__IMAGE__|$$REF|" $(VER_DEPLOY_RUN) | kubectl --context $(VER_CTX) create -f - -o jsonpath='{.metadata.name}'); \
	echo "PipelineRun $$RUN gestartet"; \
	tkn --context $(VER_CTX) pipelinerun logs -f $$RUN; \
	[ "$$(kubectl --context $(VER_CTX) get pipelinerun $$RUN -o jsonpath='{.status.conditions[0].status}')" = True ] \
		|| { echo "PipelineRun $$RUN fehlgeschlagen"; exit 1; }; \
	kubectl --context $(VER_CTX) rollout status deployment/demo-app -n deploy --timeout=2m \
		|| { echo "Neue Pods nicht zugelassen:"; kubectl --context $(VER_CTX) get events -n deploy \
			--field-selector reason=FailedCreate --sort-by=.lastTimestamp | tail -3; exit 1; }
