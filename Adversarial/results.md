# Ergebnisse adversariale Tests

| Test | Variante | Outcome | Detail |
|---|---|---|---|
| tjactions-ref-redirect | baseline | vulnerable | Schadcode erreichbar (/.well-known/renovate, zweifach Base64), Marker bestätigt; Tarnung intakt; main -> 6e99502018 als renovate[bot] |
| tjactions-ref-redirect | hardened | blocked | Umlenkung von main abgelehnt: `git -C /var/folders/jd/fkqzhjwx07v02sd_k942mxcr0000gn/T/adv-tjactions-ref-redirect-vewcpzm_/demo-app push --force origin 930ddeaa4ca5cefabbcc5c9c3b000edcb7d07459:refs/heads/main` exit 1: error: failed to push some refs to 'http://localhost:3001/VCSadmin/demo-app.git' |
