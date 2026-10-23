# Testaufbau der adversarialen Tests

NPM_INDEX := Adversarial/npm-index.yaml

##@ Adversariale Tests: Testaufbau
.PHONY: npm-index npm-index-conventional npm-index-verified

npm-index: npm-index-conventional npm-index-verified ## npm-Index (Testaufbau T3) in beiden Clustern anlegen

npm-index-conventional: ## npm-Index (Testaufbau T3) im Cluster der konventionellen Kette anlegen
	kubectl --context $(CONV_CTX) apply -f $(NPM_INDEX)
	kubectl --context $(CONV_CTX) rollout status deployment/npm-index -n npm --timeout=2m

npm-index-verified:   ## npm-Index (Testaufbau T3) im Cluster der verifizierbaren Kette anlegen
	kubectl --context $(VER_CTX) apply -f $(NPM_INDEX)
	kubectl --context $(VER_CTX) rollout status deployment/npm-index -n npm --timeout=2m
