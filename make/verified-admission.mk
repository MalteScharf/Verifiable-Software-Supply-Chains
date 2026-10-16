# Verifizierbare Lieferkette: Zulassungskontrolle mit Kyverno (AN6, AN7)

##@ Verifizierbare Lieferkette: Zulassungskontrolle (AN6, AN7)
.PHONY: verified-kyverno verified-registry-alias verified-pruefdienst verified-admission-policy

# Version von Kyverno steht in Verified/Admission/kustomization.yaml (K1).
# Server-Side Apply, da die CRDs von Kyverno für das normale apply zu groß sind.
verified-kyverno:     ## Kyverno installieren (Zulassungskontrolle)
	kubectl kustomize Verified/Admission \
		| kubectl --context $(VER_CTX) apply --server-side -f -
	kubectl --context $(VER_CTX) wait --for=condition=Available deployment --all \
		-n kyverno --timeout=5m
	kubectl --context $(VER_CTX) get pods -n kyverno

# Einheitlicher Registry-Name für Knoten und Kyverno.
# Pods nennen Images über registry.registry.svc.cluster.local:5000, den Namen,
# unter dem kaniko pusht und der im Herkunftsnachweis steht. Kyverno erreicht
# ihn über das Cluster-DNS. Die Container-Runtime der Knoten nimmt nicht am
# Cluster-DNS teil und wird über hosts.toml auf den NodePort umgeleitet.
REGISTRY_NAME := registry.registry.svc.cluster.local:5000
VER_CLUSTER   := software-supply-chain-verified

verified-registry-alias: ## Registry-Namen auf allen Knoten auf den NodePort umleiten
	@for n in $$(kind get nodes --name $(VER_CLUSTER)); do \
		echo "Knoten $$n"; \
		if ! docker exec $$n grep -q 'config_path *= *"/etc/containerd/certs.d"' /etc/containerd/config.toml; then \
			v=$$(docker exec $$n awk -F'= *' '/^version/ {print $$2; exit}' /etc/containerd/config.toml); \
			if [ "$$v" = 3 ]; then sec='[plugins."io.containerd.cri.v1.images".registry]'; \
			else sec='[plugins."io.containerd.grpc.v1.cri".registry]'; fi; \
			echo "  containerd-Konfiguration (Version $$v) um config_path ergänzen"; \
			printf '\n%s\n  config_path = "/etc/containerd/certs.d"\n' "$$sec" \
				| docker exec -i $$n sh -c 'cat >> /etc/containerd/config.toml'; \
			docker exec $$n systemctl restart containerd; \
		fi; \
		docker exec $$n mkdir -p "/etc/containerd/certs.d/$(REGISTRY_NAME)"; \
		printf '%s\n\n%s\n%s\n' 'server = "http://$(REGISTRY_NAME)"' \
			'[host."http://localhost:30500"]' '  capabilities = ["pull", "resolve"]' \
			| docker exec -i $$n sh -c 'cat > "/etc/containerd/certs.d/$(REGISTRY_NAME)/hosts.toml"'; \
		echo "  Testabruf über $(REGISTRY_NAME)"; \
		docker exec $$n crictl pull $(REGISTRY_NAME)/demo-app:latest || exit 1; \
	done

# Prüfdienst (Verified/Verifier): Image lokal bauen, in die Registry der Lieferkette
# laden und den Digest in Verified/Verifier/kustomization.yaml festhalten.
verified-pruefdienst: ## Prüfdienst bauen, in die Registry laden, per Digest ausrollen
	@if grep -q '__[A-Z]*_DIGEST__' Verified/Verifier/Dockerfile; then \
		echo "Basis-Images im Dockerfile noch nicht per Digest festgelegt, siehe Verified/readme.md"; exit 1; fi
	docker build -t pruefdienst:build Verified/Verifier
	@set -e; TMP=$$(mktemp -d); trap 'rm -rf "$$TMP"; kill $$PF 2>/dev/null' EXIT; \
	docker save pruefdienst:build -o "$$TMP/image.tar"; \
	kubectl --context $(VER_CTX) port-forward -n registry svc/registry $(VERIFY_PORT):5000 >/dev/null 2>&1 & PF=$$!; \
	for i in $$(seq 1 20); do curl -sf -o /dev/null http://localhost:$(VERIFY_PORT)/v2/ && break; sleep 0.5; done; \
	REF=$$(crane push --insecure "$$TMP/image.tar" localhost:$(VERIFY_PORT)/pruefdienst:latest); \
	D=$${REF##*@}; echo "Prüfdienst: $$D"; \
	perl -pi -e "s/digest: sha256:[0-9a-f]{64}/digest: $$D/" Verified/Verifier/kustomization.yaml
	kubectl kustomize Verified/Verifier | kubectl --context $(VER_CTX) apply -f -
	kubectl --context $(VER_CTX) rollout status deployment/pruefdienst -n verifier --timeout=3m

verified-admission-policy: ## Richtlinie der Zulassungskontrolle anwenden (AN6, AN7)
	kubectl --context $(VER_CTX) apply -f Verified/Admission/policies/
	kubectl --context $(VER_CTX) wait --for=condition=Ready clusterpolicy --all --timeout=60s
