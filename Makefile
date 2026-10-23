# Befehle für beide Ausbaustufen. Aufruf immer im Hauptordner des Repos.
# Die Befehle sind nach Ausbaustufe und Anforderung auf die Dateien in make/
# verteilt. Jeder Befehl nutzt einen festen kubectl-Kontext, damit er nie
# versehentlich im falschen Cluster läuft.
#
# Übersicht aller Befehle: make help

# Ohne Angabe eines Ziels nur die Übersicht zeigen und nichts ausführen
.DEFAULT_GOAL := help

include make/common.mk
include make/conventional.mk
include make/verified-base.mk
include make/verified-trust.mk
include make/verified-build.mk
include make/verified-chains.mk
include make/verified-sbom.mk
include make/verified-admission.mk
include make/adversarial.mk

##@ Allgemein
.PHONY: help
help:                 ## Übersicht aller Befehle anzeigen
	@awk 'BEGIN {FS = ":.*## "} \
		/^##@/ {printf "\n%s\n", substr($$0, 5)} \
		/^[a-zA-Z0-9_-]+:.*## / {printf "  %-30s %s\n", $$1, $$2}' $(MAKEFILE_LIST)
	@echo
