# Ergebnisse: Tests der Stückliste (AN5)

Ausgeführt am 2026-10-15 10:48

| Nr. | Fall | Erwartet | Ergebnis | Meldung des Verifiers | Bewertung |
|---|---|---|---|---|---|
| 1 | Normaler Build | zugelassen | zugelassen | alle sechs Schritte ok | erwartet |
| 2 | Image ohne Stückliste im Herkunftsnachweis | Schritt 4 | Schritt 4 | keine Stückliste im Herkunftsnachweis | erwartet |
| 3 | Gefälschte Stückliste unter dem Tag .sbom abgelegt | zugelassen | zugelassen | alle sechs Schritte ok | erwartet |
| 5 | Simulierte Meldung für ein Paket im Image (ms@2.0.0) | Schritt 6 | Schritt 6 | gemeldete bösartige Komponenten: ms@2.0.0 TEST-AN5B-0001 | erwartet |
| 6 | Index der Meldeliste in der Registry ausgetauscht | Schritt 6 | Schritt 6 | gemeldete bösartige Komponenten: ms@2.0.0 TEST-AN5B-0001 | erwartet |
| 4 | Zusätzliches Paket im Dockerfile (apk add), freigegeben | Schritt 5 | Schritt 5 | Komponenten nicht in der Abhängigkeitsdefinition: pkg:apk/alpine/alpine-baselayout-data@3.7.2-r0 pkg:apk/alpine/alpine-baselayout@3.7.2-r0 pkg:apk/alpine/alpine-keys@2.6-r0 pkg:apk/alpine/alpine-release@3.23.4-r0 pkg:apk/alpine/apk-tools@3.0.6-r0 pkg:apk/alpine/brotli-libs@1.2.0-r0 pkg:apk/alpine/busybox-binsh@1.37.0-r30 pkg:apk/alpine/busybox@1.37.0-r30 pkg:apk/alpine/c-ares@1.34.8-r0 pkg:apk/alpine/ca-certificates-bundle@20260413-r0 pkg:apk/alpine/curl@8.22.0-r0 pkg:apk/alpine/libapk@3.0.6-r0 pkg:apk/alpine/libcrypto3@3.5.6-r0 pkg:apk/alpine/libcurl@8.22.0-r0 pkg:apk/alpine/libgcc@15.2.0-r2 pkg:apk/alpine/libidn2@2.3.8-r0 pkg:apk/alpine/libpsl@0.21.5-r3 pkg:apk/alpine/libssl3@3.5.6-r0 pkg:apk/alpine/libstdc%2B%2B@15.2.0-r2 pkg:apk/alpine/libunistring@1.4.1-r0 pkg:apk/alpine/musl-utils@1.2.5-r23 pkg:apk/alpine/musl@1.2.5-r23 pkg:apk/alpine/nghttp2-libs@1.69.0-r0 pkg:apk/alpine/scanelf@1.3.8-r2 pkg:apk/alpine/ssl_client@1.37.0-r30 pkg:apk/alpine/zlib@1.3.2-r0 pkg:apk/alpine/zstd-libs@1.5.7-r2 | erwartet |
| 7 | Task sbom ohne Zugriff auf den Signaturschlüssel | kein Zugriff | kein Zugriff | Dienstkonto default:default, get secrets no, list secrets no (Namespace tekton-chains) | erwartet |
| 8 | Erneuter Build vom freigegebenen Commit | zugelassen | zugelassen | alle sechs Schritte ok | erwartet |

Abweichungen: 0
