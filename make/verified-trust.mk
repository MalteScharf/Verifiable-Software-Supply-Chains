# Verifizierbare Lieferkette: Trusted Key Store (AN1, AN2b) und Freigabe (AN2b)

# Authorizer (AN2b): eigene Identität und eigener Signaturschlüssel
AUTHORIZER_EMAIL := authorizer@example.com
AUTHORIZER_KEY   := $(HOME)/.ssh/authorizer_signing.pub

# Trusted Key Store: eine ConfigMap im Namespace trust, gelesen von diesen Prüfern
TRUST_FILES   := allowed_signers_producer allowed_signers_authorizer build_platform.pub build_definition
TRUST_READERS := system:serviceaccount:gitea:default system:serviceaccount:default:default

##@ Verifizierbare Lieferkette: Vertrauen und Freigabe
.PHONY: verified-check-trust verified-approve

verified-check-trust: ## Prüft Inhalt, Lese- (TK3) und Schreibrechte (TK2) des Trusted Key Store
	@fail=0; \
	for f in $(TRUST_FILES); do \
		want=$$(shasum -a 256 < Verified/Trust/$$f | cut -d' ' -f1); \
		have=$$(kubectl --context $(VER_CTX) -n trust get configmap trusted-key-store -o json \
			| jq -j --arg k "$$f" '.data[$$k]' | shasum -a 256 | cut -d' ' -f1); \
		if [ ! -s Verified/Trust/$$f ]; then echo "Inhalt $$f: LEER"; fail=1; \
	elif [ "$$have" = "$$want" ]; then echo "Inhalt $$f: identisch"; \
		else echo "Inhalt $$f: ABWEICHEND"; fail=1; fi; \
	done; \
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

verified-approve:     ## Freigabe (AN2b): Authorizer signiert einen Tag auf REV und pusht ihn
	@if git -C $(DEMO_DIR) rev-parse -q --verify "refs/tags/approved-$(REV)" >/dev/null; then \
		echo "Tag approved-$(REV) existiert bereits, wird nur übertragen"; \
	else \
		git -C $(DEMO_DIR) -c user.name=Authorizer -c user.email=$(AUTHORIZER_EMAIL) \
			-c gpg.format=ssh -c user.signingkey=$(AUTHORIZER_KEY) \
			tag -s -m "Freigabe für Build" approved-$(REV) $(REV); \
	fi
	git -C $(DEMO_DIR) push origin approved-$(REV)
