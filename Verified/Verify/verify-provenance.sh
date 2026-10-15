#!/bin/sh
# Vorläufiger Verifier für Herkunftsnachweis (AN4) und Stückliste (AN5).
# Prüft für ein Image in der Registry die Schritte aus Abschnitt 6.4.2 und 6.4.3:
#   1. Echtheit und Bindung: Nachweis ist mit dem Schlüssel der Build-Plattform
#      signiert, gehört zum Digest des Images und stammt von der erwarteten builder.id
#   2. Freigabe: das enthaltene Tag-Objekt ist vom Authorizer signiert und nennt
#      denselben Commit wie der Build-Auftrag
#   3. Build-Definition: Digests von Pipeline und Tasks entsprechen der Referenzliste
#   4. Stückliste: über ihren Digest im Herkunftsnachweis gebunden und unverändert
#   5. Abhängigkeitsdefinition (AN5a): jede Komponente außerhalb des Basis-Images
#      steht im Lockfile des freigegebenen Commits
#   6. Meldeliste (AN5b): keine npm-Komponente ist als bösartig gemeldet
# Alle Prüfgrundlagen stammen aus dem Trusted Key Store, nicht von der Build-Plattform.
#
# Aufruf (über make verified-verify, das die Registry per Port-Weiterleitung erreichbar macht):
#   verify-provenance.sh <registry> <repository> [digest]
# Ohne Digest wird das Image geprüft, auf das der Tag latest zeigt.
set -eu

REGISTRY=$1
REPO=$2
DIGEST=${3:-}
TKS=$(cd "${TKS:-Verified/Trust}" && pwd)
EXPECTED_BUILDER=${EXPECTED_BUILDER:-https://software-supply-chain-verified/tekton-chains}
VCS_URL=${VCS_URL:-http://localhost:3001/VCSadmin/demo-app.git}
HERE=$(cd "$(dirname "$0")" && pwd)

fail() { echo "ABGELEHNT: $*"; exit 1; }
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Zu prüfendes Image bestimmen
if [ -z "$DIGEST" ]; then
  DIGEST=$(curl -sfI \
    -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "http://$REGISTRY/v2/$REPO/manifests/latest" \
    | awk 'tolower($1)=="docker-content-digest:" {print $2}' | tr -d '\r')
  [ -n "$DIGEST" ] || fail "Digest von $REPO:latest nicht ermittelbar"
fi
IMAGE="$REGISTRY/$REPO@$DIGEST"
echo "Prüfe $IMAGE"

# 1. Echtheit und Bindung
cosign verify-attestation --key "$TKS/build_platform.pub" \
  --type https://slsa.dev/provenance/v1 --insecure-ignore-tlog=true \
  --allow-insecure-registry --allow-http-registry "$IMAGE" \
  > "$WORK/envelopes" 2> "$WORK/cosign.log" \
  || fail "kein gültig signierter Herkunftsnachweis der Build-Plattform (cosign: $(grep -m1 '^Error:' "$WORK/cosign.log" | sed 's/^Error: //'))"
head -1 "$WORK/envelopes" | jq -r '.payload' | base64 -d > "$WORK/statement.json"
jq -e --arg d "${DIGEST#sha256:}" '[.subject[].digest.sha256] | index($d) != null' \
  "$WORK/statement.json" > /dev/null || fail "Nachweis gehört nicht zum Digest $DIGEST"
BUILDER=$(jq -r '.predicate.runDetails.builder.id' "$WORK/statement.json")
[ "$BUILDER" = "$EXPECTED_BUILDER" ] || fail "unerwartete builder.id: $BUILDER"
echo "1. Echtheit und Bindung: ok (builder.id $BUILDER)"

# 2. Freigabe
REV=$(jq -r '.predicate.buildDefinition.externalParameters.runSpec.params[]
  | select(.name == "revision") | .value' "$WORK/statement.json")
echo "$REV" | grep -Eqx '[0-9a-f]{40}' || fail "Build-Auftrag nennt keinen Commit-Hash: $REV"
jq -j '.predicate.runDetails.byproducts[] | select(.name | endswith("/AUTHORIZATION_TAG"))
  | .content' "$WORK/statement.json" | base64 -d | jq -j . > "$WORK/tag"
[ -s "$WORK/tag" ] || fail "kein Autorisierungsnachweis im Herkunftsnachweis"
[ "$(head -1 "$WORK/tag")" = "object $REV" ] \
  || fail "Autorisierungsnachweis nennt einen anderen Commit als der Build-Auftrag"
git init -q "$WORK/repo"
TAG_SHA=$(git -C "$WORK/repo" hash-object -t tag -w "$WORK/tag")
git -C "$WORK/repo" -c "gpg.ssh.allowedSignersFile=$TKS/allowed_signers_authorizer" \
  verify-tag "$TAG_SHA" > /dev/null 2>&1 \
  || fail "Autorisierungsnachweis ist nicht von einem Authorizer signiert"
echo "2. Freigabe: ok (Commit $REV)"

# 3. Build-Definition
jq -r '.predicate.buildDefinition.resolvedDependencies[]
  | select(.name == "pipeline" or .name == "pipelineTask")
  | (.uri | split("@")[0] | split("/") | .[-2:] | join("/")) + " sha256:" + .digest.sha256' \
  "$WORK/statement.json" | LC_ALL=C sort > "$WORK/build_definition"
diff "$TKS/build_definition" "$WORK/build_definition" > "$WORK/diff" \
  || fail "Build-Definition weicht von der Referenzliste ab
$(cat "$WORK/diff")"
echo "3. Build-Definition: ok ($(wc -l < "$WORK/build_definition" | tr -d ' ') Einträge)"

# 4. Stückliste: Echtheit und Bindung (AN5)
# Der Digest der Stückliste steht im signierten Herkunftsnachweis (Result
# SBOM_DIGEST des Tasks sbom). Die Stückliste wird nur über diesen Digest geladen.
SBOM_DIGEST=$(jq -r '[.predicate.runDetails.byproducts[] | select(.name | endswith("/SBOM_DIGEST")) | .content]
  | if length == 1 then .[0] else empty end' "$WORK/statement.json" | base64 -d | jq -r .)
echo "$SBOM_DIGEST" | grep -Eqx 'sha256:[0-9a-f]{64}' || fail "keine Stückliste im Herkunftsnachweis"
crane blob --insecure "$REGISTRY/$REPO@$SBOM_DIGEST" > "$WORK/sbom.json" 2> /dev/null \
  || fail "Stückliste $SBOM_DIGEST nicht in der Registry"
[ "sha256:$(shasum -a 256 < "$WORK/sbom.json" | cut -d' ' -f1)" = "$SBOM_DIGEST" ] \
  || fail "Stückliste weicht vom Digest im Herkunftsnachweis ab"
echo "4. Stückliste: ok ($SBOM_DIGEST, $(jq '[.components[] | select(.purl)] | length' "$WORK/sbom.json") Komponenten)"

# 5. Abgleich mit der Abhängigkeitsdefinition (AN5a)
# Lockfile und Dockerfile stammen aus dem freigegebenen Commit im VCS. Komponenten
# aus den Schichten des Basis-Images gelten als erwartet, da das Basis-Image über
# seinen Digest festgelegt ist (AN3). Jede andere Komponente muss im Lockfile stehen.
git clone -q --bare "$VCS_URL" "$WORK/src.git" 2> /dev/null || fail "VCS $VCS_URL nicht erreichbar"
git -C "$WORK/src.git" cat-file -e "$REV^{commit}" 2> /dev/null || fail "Commit $REV nicht im VCS"
git -C "$WORK/src.git" show "$REV:package-lock.json" > "$WORK/lock.json" 2> /dev/null \
  || fail "kein package-lock.json im Commit $REV"
BASE=$(git -C "$WORK/src.git" show "$REV:Dockerfile" | awk 'toupper($1) == "FROM" {print $2; exit}')
crane config --insecure "$IMAGE" > "$WORK/image-config.json"
PLATFORM=$(jq -r '.os + "/" + .architecture + (if .variant then "/" + .variant else "" end)' "$WORK/image-config.json")
crane config --platform "$PLATFORM" "$BASE" > "$WORK/base-config.json" 2> /dev/null \
  || fail "Basis-Image $BASE nicht abrufbar"
jq -e --slurpfile b "$WORK/base-config.json" \
  '.rootfs.diff_ids[:($b[0].rootfs.diff_ids | length)] == $b[0].rootfs.diff_ids' \
  "$WORK/image-config.json" > /dev/null || fail "Image baut nicht auf dem Basis-Image $BASE auf"
jq -r --slurpfile b "$WORK/base-config.json" '$b[0].rootfs.diff_ids as $base
  | .components[] | select(.purl)
  | select([.properties[]? | select(.name | test("^syft:location:[0-9]+:layerID$")) | .value]
      | length == 0 or any(. as $l | ($base | index($l)) == null))
  | .purl | split("?")[0] | gsub("%40"; "@")' "$WORK/sbom.json" | LC_ALL=C sort -u > "$WORK/app.txt"
jq -r '.packages | to_entries[]
  | "pkg:npm/" + (if .key == "" then .value.name else (.value.name // (.key | sub(".*node_modules/"; ""))) end)
    + "@" + .value.version' "$WORK/lock.json" | LC_ALL=C sort -u > "$WORK/lock.txt"
LC_ALL=C comm -23 "$WORK/app.txt" "$WORK/lock.txt" > "$WORK/unexpected.txt"
[ ! -s "$WORK/unexpected.txt" ] || fail "Komponenten nicht in der Abhängigkeitsdefinition:
$(cat "$WORK/unexpected.txt")"
echo "5. Abhängigkeitsdefinition: ok ($(wc -l < "$WORK/app.txt" | tr -d ' ') Komponenten der Anwendung im Lockfile, Basis-Image $(jq '.rootfs.diff_ids | length' "$WORK/base-config.json") Schichten)"

# 6. Abgleich mit gemeldeten bösartigen Komponenten (AN5b)
# Der Index der OpenSSF-Meldeliste wird über seinen Digest aus dem Trusted Key
# Store geladen. Geprüft werden alle npm-Komponenten, auch die des Basis-Images.
MAL_DIGEST=$(awk '$1 == "digest" {print $2}' "$TKS/malicious_packages")
MAL_COMMIT=$(awk '$1 == "commit" {print $2}' "$TKS/malicious_packages")
echo "$MAL_DIGEST" | grep -Eqx 'sha256:[0-9a-f]{64}' || fail "kein Index der Meldeliste im Trusted Key Store"
crane blob --insecure "$REGISTRY/malicious-packages@$MAL_DIGEST" > "$WORK/malicious.json" 2> /dev/null \
  || fail "Index der Meldeliste $MAL_DIGEST nicht in der Registry"
[ "sha256:$(shasum -a 256 < "$WORK/malicious.json" | cut -d' ' -f1)" = "$MAL_DIGEST" ] \
  || fail "Index der Meldeliste weicht vom Digest im Trusted Key Store ab"
jq --slurpfile idx "$WORK/malicious.json" -f "$HERE/malicious-match.jq" "$WORK/sbom.json" > "$WORK/match.json"
[ "$(jq '.treffer | length' "$WORK/match.json")" = 0 ] || fail "gemeldete bösartige Komponenten:
$(jq -r '.treffer[]' "$WORK/match.json")"
echo "6. Meldeliste: ok ($(jq .geprueft "$WORK/match.json") npm-Pakete, 0 Treffer, Stand $(echo "$MAL_COMMIT" | cut -c1-12))"

echo "ZUGELASSEN: $IMAGE"
