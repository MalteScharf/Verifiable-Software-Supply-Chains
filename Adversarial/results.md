# Ergebnisse adversariale Tests

| Test | Variante | Outcome | Detail |
|---|---|---|---|
| uaparser-image-bypass | baseline | vulnerable | Fremdes Image docker.io/library/busybox:1.36 ohne Herkunftsnachweis zugelassen (Namespace deploy, Phase Running) |
| uaparser-image-bypass | hardened | blocked | Zulassung abgelehnt: admission webhook "mutate.kyverno.svc-fail" denied the request: resource Pod/deploy/t4-uaparser was blocked due to the following policies verified-images: herkunftsnachweis: 'image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: no matching attestations: ' |
