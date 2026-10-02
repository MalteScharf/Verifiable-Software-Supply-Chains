#!/bin/sh
# Pre-receive-Hook (AN1): Jeder neue Commit muss gültig signiert sein, und zwar
# vom Autor selbst mit einem Schlüssel aus dem Trusted Key Store.
SA=/var/run/secrets/kubernetes.io/serviceaccount
TKS=$(mktemp); trap 'rm -f $TKS' EXIT

# Trusted Key Store über die Kubernetes-API lesen (Leserecht: trust-reader)
curl -sf --cacert $SA/ca.crt -H "Authorization: Bearer $(cat $SA/token)" \
  https://kubernetes.default.svc/api/v1/namespaces/trust/configmaps/trusted-key-store \
  | sed -nE 's/.*"allowed_signers_producer": *"(([^"\\]|\\.)*)".*/\1/p' \
  | sed 's/\\"/"/g; s/\\n/\n/g' > $TKS
[ -s $TKS ] || { echo "Abgelehnt: Trusted Key Store nicht lesbar"; exit 1; }

# Alle neuen Commits prüfen: gültige Signatur (G) und Signierender = Autor
while read old new ref; do
  [ "$new" = 0000000000000000000000000000000000000000 ] && continue
  for c in $(git rev-list $new --not --all); do
    set -- $(git -c gpg.ssh.allowedSignersFile=$TKS log -1 --format='%G? %GS %ae' $c)
    [ "$1" = G ] && [ "$2" = "$3" ] || { echo "Abgelehnt: Commit $c nicht gültig signiert"; exit 1; }
  done
done
