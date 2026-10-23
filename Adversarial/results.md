# Ergebnisse adversariale Tests

| Test | Variante | Outcome | Detail |
|---|---|---|---|
| torchtriton-dependency-confusion | baseline | vulnerable | bösartiges express@4.22.4 aufgeloest und erreichbar (/.triton), Marker bestaetigt; Tarnung intakt; im Pod: express@4.22.4 |
| torchtriton-dependency-confusion | hardened | blocked | Marker nicht erreichbar; im Pod: express@4.22.3, Angreifer-Version war 4.22.4 |
