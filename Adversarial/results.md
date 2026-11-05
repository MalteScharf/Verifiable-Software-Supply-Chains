# Ergebnisse adversariale Tests

| Test | Variante | Outcome | Detail |
|---|---|---|---|
| tjactions-signed-redirect | baseline | vulnerable | Schadcode erreichbar (/.well-known/renovate, zweifach Base64), Marker bestätigt; Tarnung intakt; main -> eca52a7886 (signiert, nicht freigegeben) |
| tjactions-signed-redirect | hardened | blocked | Distribute-Pipeline nicht erfolgreich (distribute-run-xlrj6, abgebrochen in verify-authorization) |
