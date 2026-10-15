#!/bin/sh
# Vorläufiger Verifier für den Herkunftsnachweis (AN4).
# Prüft für ein Image in der Registry die drei Schritte aus Abschnitt 6.4.2:
#   1. Echtheit und Bindung: Nachweis ist mit dem Schlüssel der Build-Plattform
#      signiert, gehört zum Digest des Images und stammt von der erwarteten builder.id
#   2. Freigabe: das enthaltene Tag-Objekt ist vom Authorizer signiert und nennt
#      denselben Commit wie der Build-Auftrag
#   3. Build-Definition: Digests von Pipeline und Tasks entsprechen der Referenzliste
# Alle Prüfgrundlagen stammen aus dem Trusted Key Store, nicht von der Build-Plattform.
#
# Aufruf (über make verified-verify, das die Registry per Port-Weiterleitung erreichbar macht):
#   verify-provenance.sh <registry> <repository> [digest]
# Ohne Digest wird das Image geprüft, auf das der Tag latest zeigt.
set -eu

REGISTRY=$1
REPO=$2
DIGEST=${3:-}
TKS=${TKS:-Verified/Trust}
EXPECTED_BUILDER=${EXPECTED_BUILDER:-https://software-supply-chain-verified/tekton-chains}

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
git -C "$WORK/repo" -c "gpg.ssh.allowedSignersFile=$PWD/$TKS/allowed_signers_authorizer" \
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

echo "ZUGELASSEN: $IMAGE"
