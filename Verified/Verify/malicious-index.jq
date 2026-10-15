# Kompakter Index der OpenSSF-Meldeliste (AN5b).
# Eingabe: alle OSV-Meldungen aus osv/malicious/npm hintereinander.
# Ausgabe: ein Objekt Paketname -> Liste der Meldungen mit Kennung und
# betroffenen Versionen (versions) bzw. Bereichen (ranges, OSV-Ereignisse).
# Beschreibungen, Fundstellen und Zeitstempel werden weggelassen.
reduce (inputs | select(has("withdrawn") | not) | .id as $id
  | .affected[]? | select(.package.ecosystem == "npm")
  | {n: .package.name,
     e: ({id: $id}
         + (if (.versions // []) | length > 0 then {versions} else {} end)
         + ([.ranges[]? | select(.type == "SEMVER" or .type == "ECOSYSTEM") | .events]
            | if length > 0 then {ranges: .} else {} end))}) as $x
  ({}; .[$x.n] += [$x.e])
