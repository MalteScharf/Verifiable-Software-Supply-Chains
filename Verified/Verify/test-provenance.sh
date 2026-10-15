#!/bin/sh
# Tests des Herkunftsnachweises (AN4). Aufruf im Hauptordner: make verified-test-provenance
#
# Fall 1  Normaler Build                                   -> zugelassen
# Fall 2  Image an der Pipeline vorbei veröffentlicht (T4)  -> Schritt 1
# Fall 3  Gefälschter Nachweis mit eigenem Schlüssel        -> Schritt 1
# Fall 4  Echter Nachweis an fremdes Image kopiert          -> Schritt 1
# Fall 5  Nachweis aus älterer Pipeline ohne Freigabe       -> Schritt 2
# Fall 6  Manipulierter Task im Build (exit 0)              -> Schritt 3
# Fall 7  Schlüsseltrennung (Pipeline, Gitea)               -> kein Zugriff
# Fall 8  Wiederherstellung und erneuter Build              -> zugelassen
#
# Das Skript verändert die Registry (Tag latest) und vorübergehend den Task
# verify-signatures. Am Ende wird beides durch einen neuen Build wiederhergestellt.
set -u

CTX=kind-software-supply-chain-verified
PORT=15000
REG=localhost:$PORT
REPO=demo-app
# Image aus dem zweiten Vortest: gebaut mit einer Pipeline ohne Freigabe im Nachweis
OLD_IMAGE=sha256:c71f8202e8477c46642056f27b1b43b7bd13a80cbdfd3e1bb0f74075379596dc

RESULT=Verified/Verify/test-provenance-results.md
mkdir -p Verified/spike
LOG=Verified/spike/test-provenance.log
W=$(mktemp -d)
: > "$LOG"
TASK_CHANGED=0

cleanup() {
  [ "$TASK_CHANGED" = 1 ] && kubectl --context $CTX apply -f Verified/Build/tasks/verify-signatures.yaml >> "$LOG" 2>&1
  [ -n "${PF:-}" ] && kill "$PF" 2>/dev/null
  rm -rf "$W"
}
trap cleanup EXIT INT TERM

log() { echo "$*" | tee -a "$LOG"; }

for tool in kubectl jq cosign crane curl git; do
  command -v $tool >/dev/null || { echo "Werkzeug fehlt: $tool"; exit 1; }
done
log "cosign: $(cosign version 2>/dev/null | awk '/GitVersion/ {print $2}')"
log "crane: $(crane version 2>/dev/null)"

kubectl --context $CTX port-forward -n registry svc/registry $PORT:5000 >/dev/null 2>&1 &
PF=$!
for i in $(seq 1 20); do curl -sf -o /dev/null "http://$REG/v2/" && break; sleep 0.5; done

latest_digest() {
  curl -sfI -H 'Accept: application/vnd.oci.image.manifest.v1+json' \
    -H 'Accept: application/vnd.docker.distribution.manifest.v2+json' \
    "http://$REG/v2/$REPO/manifests/latest" \
    | awk 'tolower($1)=="docker-content-digest:" {print $2}' | tr -d '\r'
}

# Prüft ein Image und liefert "zugelassen" oder "Schritt N" sowie die Meldung
VERDICT=""; MESSAGE=""
check() {
  out=$(sh Verified/Verify/verify-provenance.sh $REG $REPO "$1" 2>&1)
  echo "$out" >> "$LOG"
  if echo "$out" | grep -q '^ZUGELASSEN'; then
    VERDICT="zugelassen"; MESSAGE="alle drei Schritte ok"
  else
    n=$(echo "$out" | grep -c '^[123]\. .*: ok')
    VERDICT="Schritt $((n + 1))"
    MESSAGE=$(echo "$out" | grep '^ABGELEHNT' | head -1 | sed 's/^ABGELEHNT: //')
  fi
}

# Wartet, bis Chains den letzten Build signiert hat
wait_signed() {
  run=$(kubectl --context $CTX get pipelinerun --sort-by=.metadata.creationTimestamp -o name \
    | grep distribute-run | tail -1)
  for i in $(seq 1 36); do
    [ "$(kubectl --context $CTX get "$run" -o jsonpath='{.metadata.annotations.chains\.tekton\.dev/signed}')" = true ] \
      && { sleep 3; return 0; }
    sleep 5
  done
  return 1
}

build() {
  log "Build läuft ..."
  make --no-print-directory -s verified-build >> "$LOG" 2>&1 || { log "Build fehlgeschlagen"; return 1; }
  wait_signed || { log "Chains hat nicht signiert"; return 1; }
}

echo "# Ergebnisse: Tests des Herkunftsnachweises (AN4)" > "$RESULT"
echo "" >> "$RESULT"
echo "Ausgeführt am $(date '+%Y-%m-%d %H:%M')" >> "$RESULT"
echo "" >> "$RESULT"
echo "| Nr. | Fall | Erwartet | Ergebnis | Meldung des Verifiers | Bewertung |" >> "$RESULT"
echo "|---|---|---|---|---|---|" >> "$RESULT"
FAILS=0
record() {  # Nr, Fall, Erwartet
  if [ "$VERDICT" = "$3" ]; then ok="erwartet"; else ok="ABWEICHUNG"; FAILS=$((FAILS + 1)); fi
  echo "| $1 | $2 | $3 | $VERDICT | $(echo "$MESSAGE" | tr '|' '/') | $ok |" >> "$RESULT"
  log "Fall $1 ($2): $VERDICT, $ok"
}

# Fall 1: normaler Build (aktuelles latest)
GOOD=$(latest_digest)
log "Ausgangsimage: $GOOD"
check "$GOOD"; record 1 "Normaler Build" "zugelassen"
[ "$VERDICT" = zugelassen ] || { log "Ausgangszustand nicht zugelassen, Abbruch"; exit 1; }
GOOD_HEX=${GOOD#sha256:}

# Fall 2: verändertes Image an der Pipeline vorbei unter latest veröffentlichen
out=$(crane mutate --insecure "$REG/$REPO@$GOOD" --label angriff=t4 -t "$REG/$REPO:latest" 2>>"$LOG")
BAD=${out##*@}
log "Manipuliertes Image: $BAD"
check "$(latest_digest)"; record 2 "Image an der Pipeline vorbei veröffentlicht (T4)" "Schritt 1"
BAD_HEX=${BAD#sha256:}

# Fall 3: gefälschter Nachweis, signiert mit eigenem Schlüssel
make --no-print-directory -s verified-provenance 2>/dev/null | jq '.predicate' > "$W/predicate.json"
( cd "$W" && COSIGN_PASSWORD="" cosign generate-key-pair >/dev/null 2>&1 )
if COSIGN_PASSWORD="" cosign attest --yes --key "$W/cosign.key" \
     --type https://slsa.dev/provenance/v1 --predicate "$W/predicate.json" \
     --use-signing-config=false --tlog-upload=false --new-bundle-format=false \
     --allow-insecure-registry --allow-http-registry \
     "$REG/$REPO@$BAD" >> "$LOG" 2>&1; then
  check "$BAD"; record 3 "Gefälschter Nachweis mit eigenem Schlüssel" "Schritt 1"
else
  VERDICT="nicht ausgeführt"; MESSAGE="cosign attest fehlgeschlagen, siehe Log"
  record 3 "Gefälschter Nachweis mit eigenem Schlüssel" "Schritt 1"
fi

# Fall 4: echten Nachweis des guten Images an das manipulierte Image kopieren
if crane copy --insecure "$REG/$REPO:sha256-$GOOD_HEX.att" "$REG/$REPO:sha256-$BAD_HEX.att" >> "$LOG" 2>&1; then
  check "$BAD"; record 4 "Echter Nachweis an fremdes Image kopiert" "Schritt 1"
else
  VERDICT="nicht ausgeführt"; MESSAGE="crane copy fehlgeschlagen, siehe Log"
  record 4 "Echter Nachweis an fremdes Image kopiert" "Schritt 1"
fi

# Fall 5: Image aus einer älteren Pipeline ohne Freigabe im Nachweis
check "$OLD_IMAGE"; record 5 "Nachweis aus älterer Pipeline ohne Freigabe" "Schritt 2"

# Fall 6: Task verify-signatures so verändern, dass er jede Prüfung besteht
kubectl --context $CTX get task verify-signatures -o json \
  | jq 'del(.metadata.resourceVersion, .metadata.uid, .metadata.generation,
            .metadata.creationTimestamp, .metadata.managedFields)
        | .spec.steps[-1].script = "#!/bin/sh\necho Pruefung manipuliert\nexit 0\n"' \
  | kubectl --context $CTX apply -f - >> "$LOG" 2>&1 && TASK_CHANGED=1
if [ "$TASK_CHANGED" = 1 ] && build; then
  check "$(latest_digest)"; record 6 "Manipulierter Task im Build (exit 0)" "Schritt 3"
else
  VERDICT="nicht ausgeführt"; MESSAGE="Build mit manipuliertem Task fehlgeschlagen, siehe Log"
  record 6 "Manipulierter Task im Build (exit 0)" "Schritt 3"
fi

# Wiederherstellen des Tasks
kubectl --context $CTX apply -f Verified/Build/tasks/verify-signatures.yaml >> "$LOG" 2>&1 && TASK_CHANGED=0

# Fall 7: Schlüsseltrennung
if make --no-print-directory -s verified-check-chains >> "$LOG" 2>&1; then
  VERDICT="kein Zugriff"; MESSAGE="Pipeline und Gitea dürfen Secrets in tekton-chains weder lesen noch auflisten"
else
  VERDICT="Zugriff möglich"; MESSAGE="siehe Log"
fi
record 7 "Schlüsseltrennung (Pipeline, Gitea)" "kein Zugriff"

# Fall 8: erneuter Build mit wiederhergestelltem Task
if build; then
  check "$(latest_digest)"
else
  VERDICT="nicht ausgeführt"; MESSAGE="Build fehlgeschlagen, siehe Log"
fi
record 8 "Wiederherstellung und erneuter Build" "zugelassen"

echo "" >> "$RESULT"
echo "Abweichungen: $FAILS" >> "$RESULT"
log ""
log "Fertig. Abweichungen: $FAILS. Ergebnisse in $RESULT, Details in $LOG"
