# Abgleich der npm-Komponenten einer CycloneDX-Stückliste mit dem Index der
# Meldeliste (AN5b). Aufruf: jq --slurpfile idx <index> -f malicious-match.jq <stückliste>
# Ein Paket ist betroffen, wenn seine Version in "versions" steht oder in einem
# Bereich liegt (introduced, fixed, last_affected; "0" steht für alle Versionen).
def ver: if . == "0" then [-1]
  else split("+")[0] | split("-") as $p
  | ($p[0] | split(".") | map(tonumber? // 0)) + [(if ($p|length) > 1 then 0 else 1 end), ($p[1:] | join("-"))] end;
def hit($v): ($v | ver) as $x
  | any(.versions[]?; . == $v)
    or any(.ranges[]?; . as $e
      | any($e[] | select(has("introduced")) | .introduced | ver; . as $i
        | $i <= $x
          and ([$e[] | select(has("fixed")) | .fixed | ver | select(. > $i and . <= $x)] | length == 0)
          and ([$e[] | select(has("last_affected")) | .last_affected | ver | select(. >= $i and . < $x)] | length == 0)));
$idx[0] as $i
| [.components[] | (.purl // "") | select(startswith("pkg:npm/"))
   | ltrimstr("pkg:npm/") | split("?")[0] | gsub("%40"; "@") | capture("^(?<n>.+)@(?<v>[^@]+)$")]
| unique
| { geprueft: length,
    treffer: [.[] | . as $c | ($i[$c.n] // [])[] | select(hit($c.v)) | "\($c.n)@\($c.v) \(.id)"] }
