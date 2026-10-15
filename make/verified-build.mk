# Verifizierbare Lieferkette: Build mit Prüfungen (AN1 bis AN3) und Deploy

# Build-Auftrag der verifizierbaren Kette (AN2a), nennt den Commit über __REVISION__
VER_DISTRIBUTE_RUN := Verified/Distribute/runs/run-gitea.yaml

##@ Verifizierbare Lieferkette: Build und Deploy
.PHONY: verified-build verified-deploy

verified-build:       ## Distribute-Pipeline im Cluster der verifizierbaren Kette (Commit über REV)
	$(call run_pipeline,$(VER_CTX),$(VER_DISTRIBUTE_RUN))

verified-deploy:      ## Deploy-Pipeline im Cluster der verifizierbaren Kette
	$(call run_pipeline,$(VER_CTX),$(DEPLOY_RUN))
