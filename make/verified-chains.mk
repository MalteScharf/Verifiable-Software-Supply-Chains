# Verifizierbare Lieferkette: Herkunftsnachweis mit Tekton Chains (AN4)

# Tekton Chains mit fester Version, damit die Umgebung reproduzierbar bleibt (K1)
TEKTON_CHAINS_VERSION := v0.29.0
CHAINS_RELEASE := https://infra.tekton.dev/tekton-releases/chains/previous/$(TEKTON_CHAINS_VERSION)/release.yaml
CHAINS_CONFIG  := Verified/Chains/chains-config.yaml

# Öffentlicher Schlüssel der Build-Plattform, Teil des Trusted Key Store
BUILD_PLATFORM_PUB := Verified/Trust/build_platform.pub

# Referenzliste der Build-Definition im Trusted Key Store (Digests von Pipeline und Tasks)
BUILD_DEFINITION := Verified/Trust/build_definition
# Lokaler Port für die Registry während der Prüfung (5000 ist unter macOS oft belegt)
VERIFY_PORT := 15000

# Konten, die den Signaturschlüssel nicht lesen dürfen (H1): Pipeline und Gitea
KEY_DENIED := system:serviceaccount:default:default system:serviceaccount:gitea:default

# Gibt den Herkunftsnachweis aus der Annotation am PipelineRun aus
# (Standard: letzter Build der Distribute-Pipeline, sonst RUN=<name>)
SHOW_PROVENANCE = R="$(RUN)"; \
	[ -n "$$R" ] || R=$$(kubectl --context $(VER_CTX) get pipelinerun \
		--sort-by=.metadata.creationTimestamp -o name | grep distribute-run | tail -1); \
	R=$${R\#pipelinerun.tekton.dev/}; \
	echo "Herkunftsnachweis von $$R" >&2; \
	kubectl --context $(VER_CTX) get pipelinerun $$R -o json \
	| jq -r '.metadata.annotations | to_entries[] | select(.key | startswith("chains.tekton.dev/payload")) | .value' \
	| base64 -d | jq .

##@ Verifizierbare Lieferkette: Herkunftsnachweis (AN4)
.PHONY: verified-chains verified-chains-key verified-check-chains verified-provenance \
        verified-pin-build-definition verified-verify verified-test-provenance

verified-chains:      ## Tekton Chains installieren, konfigurieren und Signaturschlüssel anlegen
	kubectl --context $(VER_CTX) apply -f $(CHAINS_RELEASE)
	kubectl --context $(VER_CTX) wait --for=condition=Available deployment --all \
		-n tekton-chains --timeout=5m
	kubectl --context $(VER_CTX) patch configmap chains-config -n tekton-chains \
		--type merge --patch-file $(CHAINS_CONFIG)
	@$(MAKE) --no-print-directory verified-chains-key
	kubectl --context $(VER_CTX) rollout restart deployment tekton-chains-controller -n tekton-chains
	kubectl --context $(VER_CTX) rollout status deployment tekton-chains-controller \
		-n tekton-chains --timeout=5m

# Der private Schlüssel wird nur im Cluster abgelegt (Secret signing-secrets im
# Namespace tekton-chains) und nie im Repository gespeichert.
verified-chains-key:  ## Signaturschlüssel der Build-Plattform anlegen (falls nötig), öffentlichen Teil in den Trusted Key Store
	@if kubectl --context $(VER_CTX) get secret signing-secrets -n tekton-chains >/dev/null 2>&1; then \
		echo "Signaturschlüssel der Build-Plattform bereits vorhanden"; \
	else \
		echo "Signaturschlüssel der Build-Plattform erzeugen"; \
		TMP=$$(mktemp -d); PW=$$(openssl rand -hex 24); \
		( cd $$TMP && COSIGN_PASSWORD=$$PW cosign generate-key-pair >/dev/null ) && \
		kubectl --context $(VER_CTX) create secret generic signing-secrets -n tekton-chains \
			--from-file=cosign.key=$$TMP/cosign.key --from-file=cosign.pub=$$TMP/cosign.pub \
			--from-literal=cosign.password=$$PW; \
		rm -rf $$TMP; \
	fi
	@kubectl --context $(VER_CTX) get secret signing-secrets -n tekton-chains -o json \
		| jq -r '.data["cosign.pub"]' | base64 -d > $(BUILD_PLATFORM_PUB)
	@echo "Öffentlicher Schlüssel in $(BUILD_PLATFORM_PUB), Trusted Key Store wird aktualisiert"
	kubectl kustomize Verified/Trust | kubectl --context $(VER_CTX) apply -f -

verified-check-chains: ## Prüft Schlüsseltrennung (H1) und den Schlüssel der Build-Plattform im Trusted Key Store
	@fail=0; \
	for sa in $(KEY_DENIED); do \
		echo "$$sa"; \
		for verb in get list; do \
			r=$$(kubectl --context $(VER_CTX) auth can-i $$verb secrets \
				-n tekton-chains --as=$$sa 2>/dev/null); \
			echo "  $$verb secrets in tekton-chains: $$r (Soll: no)"; \
			[ "$$r" = no ] || fail=1; \
		done; \
	done; \
	want=$$(kubectl --context $(VER_CTX) get secret signing-secrets -n tekton-chains -o json \
		| jq -r '.data["cosign.pub"]' | base64 -d | shasum -a 256 | cut -d' ' -f1); \
	have=$$(kubectl --context $(VER_CTX) -n trust get configmap trusted-key-store -o json \
		| jq -j '.data["build_platform.pub"]' | shasum -a 256 | cut -d' ' -f1); \
	if [ "$$want" = "$$have" ]; then echo "build_platform.pub im Trusted Key Store: identisch"; \
	else echo "build_platform.pub im Trusted Key Store: ABWEICHEND"; fail=1; fi; \
	if [ $$fail -eq 0 ]; then echo "ok"; else echo "FEHLER"; exit 1; fi

verified-provenance:  ## Herkunftsnachweis eines Builds anzeigen (Standard: letzter Build, sonst RUN=<name>)
	@$(SHOW_PROVENANCE)

# Der Administrator legt die Referenzliste aus einem Build fest, den er als gut kennt.
# Danach fällt jede Änderung an Pipeline oder Tasks bei der Prüfung auf, bis die
# Liste bewusst neu festgelegt wird.
verified-pin-build-definition: ## Referenzliste der Build-Definition aus dem letzten Build festlegen (RUN=<name> optional)
	@$(SHOW_PROVENANCE) \
		| jq -r '.predicate.buildDefinition.resolvedDependencies[] | select(.name == "pipeline" or .name == "pipelineTask") | (.uri | split("@")[0] | split("/") | .[-2:] | join("/")) + " sha256:" + .digest.sha256' \
		| LC_ALL=C sort > $(BUILD_DEFINITION).neu; \
	[ -s $(BUILD_DEFINITION).neu ] || { echo "Keine Build-Definition im Nachweis gefunden"; rm -f $(BUILD_DEFINITION).neu; exit 1; }; \
	mv $(BUILD_DEFINITION).neu $(BUILD_DEFINITION); \
	cat $(BUILD_DEFINITION)
	kubectl kustomize Verified/Trust | kubectl --context $(VER_CTX) apply -f -

verified-verify:      ## Herkunftsnachweis eines Images prüfen (Standard: demo-app:latest, sonst DIGEST=sha256:...)
	@kubectl --context $(VER_CTX) port-forward -n registry svc/registry $(VERIFY_PORT):5000 >/dev/null 2>&1 & PF=$$!; \
	trap "kill $$PF 2>/dev/null" EXIT; \
	for i in $$(seq 1 20); do curl -sf -o /dev/null http://localhost:$(VERIFY_PORT)/v2/ && break; sleep 0.5; done; \
	sh Verified/Verify/verify-provenance.sh localhost:$(VERIFY_PORT) demo-app $(DIGEST)

verified-test-provenance: ## Tests des Herkunftsnachweises (AN4), Ergebnis in Verified/Verify/test-provenance-results.md
	sh Verified/Verify/test-provenance.sh
