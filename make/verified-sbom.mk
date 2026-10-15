# Verifizierbare Lieferkette: Stückliste und Meldeliste (AN5)

# Meldeliste schädlicher Pakete (OpenSSF Malicious Packages, AN5b).
# Lokaler Cache nur mit dem Ordner für npm, Stand über MAL_COMMIT wählbar
# (Standard: aktueller Stand von main).
MAL_REPO   := https://github.com/ossf/malicious-packages.git
MAL_DIR    := .cache/malicious-packages
MAL_INDEX  := .cache/malicious-packages-index.json
MAL_COMMIT ?=
# Eintrag im Trusted Key Store: Commit der Liste und Digest des Index
MALICIOUS_PACKAGES := Verified/Trust/malicious_packages

##@ Verifizierbare Lieferkette: Stückliste (AN5)
.PHONY: verified-malicious-packages

# 1. Liste holen, 2. Index berechnen, 3. Index in die Registry legen,
# 4. Commit und Digest in den Trusted Key Store schreiben.
# Der Verifier lädt den Index später nur über diesen Digest.
verified-malicious-packages: ## Meldeliste holen, Index in die Registry legen, Digest in den Trusted Key Store (MAL_COMMIT optional)
	@set -e; \
	if [ ! -d $(MAL_DIR)/.git ]; then \
		echo "1) Meldeliste klonen (nur osv/malicious/npm)"; \
		git clone -q --depth 1 --filter=blob:none --sparse $(MAL_REPO) $(MAL_DIR); \
		git -C $(MAL_DIR) sparse-checkout set osv/malicious/npm; \
	fi; \
	echo "1) Meldeliste aktualisieren"; \
	git -C $(MAL_DIR) fetch -q --depth 1 --filter=blob:none origin $(or $(MAL_COMMIT),main); \
	git -C $(MAL_DIR) checkout -q --detach FETCH_HEAD; \
	COMMIT=$$(git -C $(MAL_DIR) rev-parse HEAD); \
	echo "   Stand $$COMMIT vom $$(git -C $(MAL_DIR) log -1 --format=%cs)"; \
	echo "2) Index berechnen"; \
	find $(MAL_DIR)/osv/malicious/npm -type f -name '*.json' -print0 | LC_ALL=C sort -z \
		| xargs -0 cat | jq -c -S -n -f Verified/Verify/malicious-index.jq > $(MAL_INDEX); \
	DIGEST=sha256:$$(shasum -a 256 $(MAL_INDEX) | cut -d' ' -f1); \
	echo "   $$(jq 'length' $(MAL_INDEX)) Pakete, $$(du -h $(MAL_INDEX) | cut -f1), $$DIGEST"; \
	echo "3) Index in die Registry legen"; \
	kubectl --context $(VER_CTX) port-forward -n registry svc/registry $(VERIFY_PORT):5000 >/dev/null 2>&1 & PF=$$!; \
	trap "kill $$PF 2>/dev/null" EXIT; \
	for i in $$(seq 1 20); do curl -sf -o /dev/null http://localhost:$(VERIFY_PORT)/v2/ && break; sleep 0.5; done; \
	REF=localhost:$(VERIFY_PORT)/malicious-packages:$$(echo $$COMMIT | cut -c1-12); \
	cosign upload blob -f $(MAL_INDEX) --ct application/json \
		--allow-insecure-registry --allow-http-registry $$REF >/dev/null; \
	LAYER=$$(crane manifest --insecure $$REF | jq -r '.layers[0].digest'); \
	[ "$$LAYER" = "$$DIGEST" ] || { echo "Digest in der Registry ($$LAYER) weicht vom Index ab"; exit 1; }; \
	crane blob --insecure localhost:$(VERIFY_PORT)/malicious-packages@$$DIGEST | shasum -a 256 \
		| grep -q $${DIGEST#sha256:} || { echo "Index nicht über den Digest ladbar"; exit 1; }; \
	echo "   $$REF, über den Digest ladbar"; \
	echo "4) Eintrag im Trusted Key Store"; \
	printf 'commit %s\ndigest %s\n' $$COMMIT $$DIGEST > $(MALICIOUS_PACKAGES); \
	cat $(MALICIOUS_PACKAGES); \
	kubectl kustomize Verified/Trust | kubectl --context $(VER_CTX) apply -f -

