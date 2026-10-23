# Laufzeitmessung beider Ausbaustufen (Evaluation)

##@ Laufzeitmessung
.PHONY: measure

measure:              ## Laufzeitmessung, ein Lauf je Ausbaustufe (nur eine: VARIANT=baseline oder VARIANT=hardened)
	python3 Measure/measure.py $(if $(VARIANT),--variant $(VARIANT))
