# Ergebnisse adversariale Tests

| Test | Variante | Outcome | Detail |
|---|---|---|---|
| codecov-tag-overwrite | baseline | vulnerable | Nonce-Marker bestätigt; Tag-Digest sha256:dcdae4b7ae382377bf7bc15fc6542bfe20595b0bd97c90ad31b087957c0f3e3b, Pod-Image-Digest sha256:dcdae4b7ae382377bf7bc15fc6542bfe20595b0bd97c90ad31b087957c0f3e3b |
| php-account-takeover | baseline | vulnerable | Backdoor erreichbar (Header User-Agentt), Marker bestätigt; Tarnung intakt; Commit e81e721381 als Malte Scharf |
| tjactions-ref-redirect | baseline | vulnerable | Schadcode erreichbar (/.well-known/renovate, zweifach Base64), Marker bestätigt; Tarnung intakt; main -> a93cf3cab1 als renovate[bot] |
| uaparser-image-bypass | baseline | vulnerable | Fremdes Image docker.io/library/busybox:1.36 ohne Herkunftsnachweis zugelassen (Namespace deploy, Phase Running) |
| codecov-tag-overwrite | hardened | blocked | Nonce-Marker nicht bestätigt (HTTP 404); Tag-Digest sha256:66505e4de63164e9f3fe9bc1c2a322f42ee85d1d0f51f645848ed09b1b6e6edf, Pod-Image-Digest sha256:338e1c02ea3e95d1c10d0b81f8cea74e3a6a54f9492966ad7c718a3902855024; erwartet für den Angriff sha256:66505e4de63164e9f3fe9bc1c2a322f42ee85d1d0f51f645848ed09b1b6e6edf, festgelegter Digest sha256:338e1c02ea3e95d1c10d0b81f8cea74e3a6a54f9492966ad7c718a3902855024 |
| php-account-takeover | hardened | blocked | Push abgelehnt: Abgelehnt: Commit 4c61cd6643de7b9a5aeda85cd419f14e9bcedc4c nicht gültig signiert |
| tjactions-ref-redirect | hardened | blocked | Umlenkung von main abgelehnt: Abgelehnt: Commit a33fdb05dc5a678697cad609672034517bc381ee nicht gültig signiert |
| uaparser-image-bypass | hardened | blocked | Zulassung abgelehnt: admission webhook "mutate.kyverno.svc-fail" denied the request: resource Pod/deploy/t4-uaparser was blocked due to the following policies verified-images: herkunftsnachweis: 'image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: no matching attestations: ' |
| torchtriton-dependency-confusion | baseline | vulnerable | bösartiges express@4.22.4 aufgelöst und erreichbar (/.triton), Marker bestätigt; Tarnung intakt; im Pod: express@4.22.4 |
| torchtriton-dependency-confusion | hardened | blocked | Marker nicht erreichbar; im Pod: express@4.22.3, Angreifer-Version war 4.22.4 |
