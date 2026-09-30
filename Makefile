.PHONY: build
build:       ## Distribute-Pipeline: Clone, Build, Push in die Registry
	@RUN=$$(kubectl create -f Conventional/Distribute/runs/run-gitea.yaml -o jsonpath='{.metadata.name}'); \
	echo "PipelineRun $$RUN gestartet"; \
	tkn pipelinerun logs -f $$RUN; \
	kubectl wait --for=condition=Succeeded pipelinerun/$$RUN --timeout=10m
