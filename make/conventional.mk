# Konventionelle Lieferkette (Baseline)

DISTRIBUTE_RUN := Conventional/Distribute/runs/run-gitea.yaml

##@ Konventionelle Lieferkette
.PHONY: conventional-build conventional-deploy

conventional-build:   ## Distribute-Pipeline: Clone, Build, Push in die Registry
	$(call run_pipeline,$(CONV_CTX),$(DISTRIBUTE_RUN))

conventional-deploy:  ## Deploy-Pipeline: Rollout-Restart der Demo-App
	$(call run_pipeline,$(CONV_CTX),$(DEPLOY_RUN))
