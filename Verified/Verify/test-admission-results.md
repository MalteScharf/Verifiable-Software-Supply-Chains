# Ergebnisse: Tests der Zulassungskontrolle (AN6, AN7)

Ausgeführt am 2026-10-23 11:49

| Nr. | Fall | Erwartet | Ergebnis | Meldung | Bewertung |
|---|---|---|---|---|---|
| 1 | Gutes Image über Digest | zugelassen | zugelassen | Pod zugelassen | erwartet |
| 2 | Gutes Image nur über Tag (AN6) | abgelehnt | abgelehnt | herkunftsnachweis: missing digest for registry.registry.svc.cluster.local:5000/demo-app:latest | erwartet |
| 3 | Image ohne Herkunftsnachweis | abgelehnt | abgelehnt | herkunftsnachweis: 'image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: no matching attestations: ' | erwartet |
| 4 | Image aus älterer Pipeline (Build-Definition) | abgelehnt | abgelehnt | herkunftsnachweis: 'image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: .attestations[0].attestors[0].entries[0].keys: attestation checks failed for registry.registry.svc.cluster.local:5000 | erwartet |
| 5 | Freigabe nicht von einem Authorizer (Schritt 2) | abgelehnt | abgelehnt | pruefdienst: 'Prüfdienst: Autorisierungsnachweis ist nicht von einem Authorizer signiert' | erwartet |
| 6 | Paket außerhalb des Lockfiles (Schritt 5) | abgelehnt | abgelehnt | pruefdienst: 'Prüfdienst: Komponenten nicht in der Abhängigkeitsdefinition: pkg:apk/alpine/alpine-baselayout-data@3.7.2-r0, pkg:apk/alpine/alpine-baselayout@3.7.2-r0, pkg:apk/alpine/alpine-keys@2.6-r0, pkg:apk/alpine/alp | erwartet |
| 7 | Simulierte Meldung für ms@2.0.0 (Schritt 6) | abgelehnt | abgelehnt | pruefdienst: 'Prüfdienst: gemeldete bösartige Komponenten: ms@2.0.0 TEST-AN7-0001' | erwartet |
| 8 | Fremder Namespace, Image ohne Nachweis | abgelehnt | abgelehnt | herkunftsnachweis: 'image attestations verification failed, verifiedCount: 0, requiredCount: 1, error: no matching attestations: ' | erwartet |
| 9 | Prüfdienst nicht erreichbar | abgelehnt | abgelehnt | pruefdienst: 'failed to check deny conditions: failed to substitute variables in condition key: failed to resolve result.allowed at path : failed to fetch data for APICall: failed to execute HTTP request for APICall resu | erwartet |
| 10 | Kyverno nicht erreichbar | abgelehnt | abgelehnt | Error from server (InternalError): Internal error occurred: failed calling webhook "mutate.kyverno.svc-fail": failed to call webhook: Post "https://kyverno-svc.kyverno.svc:443/mutate/fail?timeout=30s": dial tcp 10.96.32. | erwartet |
| 11 | Rechte des Deployers auf die Prüfgrundlagen | kein Zugriff | kein Zugriff | Richtlinien, Trusted Key Store, Webhooks, Kyverno, Prüfdienst, Pods in default | erwartet |
| 12 | Echtes Deployment über die Deploy-Pipeline | zugelassen | zugelassen | neuer Pod läuft mit sha256:0b8a11a3cf0b | erwartet |

Abweichungen: 0
