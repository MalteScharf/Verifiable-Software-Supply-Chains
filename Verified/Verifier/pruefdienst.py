"""Prüfdienst der Zulassungskontrolle (AN4 Schritt 2, AN5 Schritte 4 bis 6).

Kyverno prüft selbst die Referenz über den Digest (AN6), die Signatur des
Herkunftsnachweises (Schritt 1) und die Build-Definition (Schritt 3). Für alle
übrigen Schritte ruft Kyverno diesen Dienst per HTTP auf:

    POST /verify   {"images": ["<registry>/<repo>@sha256:...", ...]}
    Antwort        {"allowed": true|false, "reason": "..."}

Der Dienst nimmt nur Anfragen von Kyverno an (TokenReview). Bevor er Angaben
aus dem Herkunftsnachweis nutzt, prüft er dessen Signatur selbst. Alle
Prüfgrundlagen stammen aus dem Trusted Key Store. Kann eine Prüfung nicht
durchgeführt werden, lautet die Antwort "allowed: false" (Ablehnung im Zweifel).
"""

import base64
import hashlib
import json
import os
import re
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REGISTRY = os.environ.get("REGISTRY", "registry.registry.svc.cluster.local:5000")
VCS_URL = os.environ.get("VCS_URL", "http://gitea.gitea.svc.cluster.local:3000/VCSadmin/demo-app.git")
KYVERNO_SA = os.environ.get("KYVERNO_SA", "system:serviceaccount:kyverno:kyverno-admission-controller")
EXPECTED_BUILDER = os.environ.get("EXPECTED_BUILDER", "https://software-supply-chain-verified/tekton-chains")
INDEX_REPO = "malicious-packages"
SLSA_TYPE = "https://slsa.dev/provenance/v1"
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_API = "https://kubernetes.default.svc"
TKS_PATH = "/api/v1/namespaces/trust/configmaps/trusted-key-store"
TIMEOUT = 20


class Abgelehnt(Exception):
    """Eine Prüfung ist fehlgeschlagen oder nicht durchführbar."""


def log(**fields):
    print(json.dumps(fields, ensure_ascii=False), flush=True)


def sha256(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT, **kw)


# ---------------------------------------------------------------- Kubernetes

def k8s(method, path, body=None):
    with open(f"{SA_DIR}/token") as f:
        token = f.read()
    ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(K8S_API + path, data=data, method=method, headers={
        "Authorization": "Bearer " + token, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, context=ctx, timeout=10) as resp:
        return json.load(resp)


def authenticate(header):
    """Nur Kyverno darf den Dienst aufrufen. Das Token prüft der API-Server."""
    if not header.startswith("Bearer "):
        raise Abgelehnt("Anfrage ohne Token")
    token = header[len("Bearer "):]
    try:
        claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    except (IndexError, ValueError):
        raise Abgelehnt("Token nicht lesbar")
    aud = claims.get("aud", [])
    review = k8s("POST", "/apis/authentication.k8s.io/v1/tokenreviews", {
        "apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
        "spec": {"token": token, "audiences": [aud] if isinstance(aud, str) else aud}})
    status = review.get("status", {})
    if not status.get("authenticated") or status.get("user", {}).get("username") != KYVERNO_SA:
        raise Abgelehnt("Anfrage stammt nicht von Kyverno")


def trusted_key_store():
    return k8s("GET", TKS_PATH)["data"]


# ------------------------------------------------------------------ Registry

class _StripAuthOnRedirect(urllib.request.HTTPRedirectHandler):
    """Blobs von Docker Hub liegen hinter einer Weiterleitung zu einem CDN,
    das keinen Authorization-Header verträgt."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).netloc != urllib.parse.urlparse(req.full_url).netloc:
            new.headers.pop("Authorization", None)
            new.unredirected_hdrs.pop("Authorization", None)
        return new


_opener = urllib.request.build_opener(_StripAuthOnRedirect)
_tokens = {}

ACCEPT_MANIFEST = ", ".join([
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json"])


def _registry_url(registry):
    if registry == "docker.io":
        return "https://registry-1.docker.io"
    if registry == REGISTRY:
        return "http://" + registry        # Registry der Lieferkette ohne TLS
    return "https://" + registry


def _bearer_token(challenge, repo):
    params = dict(re.findall(r'(\w+)="([^"]*)"', challenge))
    query = {"service": params.get("service", ""), "scope": params.get("scope", f"repository:{repo}:pull")}
    url = params["realm"] + "?" + urllib.parse.urlencode(query)
    with _opener.open(url, timeout=TIMEOUT) as resp:
        body = json.load(resp)
    return body.get("token") or body.get("access_token")


def registry_get(registry, repo, kind, ref, accept=None):
    url = f"{_registry_url(registry)}/v2/{repo}/{kind}/{ref}"
    for attempt in range(2):
        headers = {"Accept": accept} if accept else {}
        if (registry, repo) in _tokens:
            headers["Authorization"] = "Bearer " + _tokens[(registry, repo)]
        try:
            with _opener.open(urllib.request.Request(url, headers=headers), timeout=TIMEOUT) as resp:
                return resp.read()
        except urllib.error.HTTPError as err:
            challenge = err.headers.get("WWW-Authenticate", "")
            if err.code == 401 and attempt == 0 and challenge.startswith("Bearer"):
                _tokens[(registry, repo)] = _bearer_token(challenge, repo)
                continue
            raise Abgelehnt(f"{registry}/{repo}: {kind} {ref} nicht abrufbar (HTTP {err.code})")
    raise Abgelehnt(f"{registry}/{repo}: keine Berechtigung")


def blob(registry, repo, digest):
    """Lädt einen Blob über seinen Digest und prüft, dass der Inhalt dazu passt."""
    data = registry_get(registry, repo, "blobs", digest)
    if sha256(data) != digest:
        raise Abgelehnt(f"Inhalt von {repo}@{digest} passt nicht zum Digest")
    return data


def image_config(registry, repo, digest, platform=None):
    manifest = json.loads(registry_get(registry, repo, "manifests", digest, ACCEPT_MANIFEST))
    if "manifests" in manifest:                       # Index über mehrere Plattformen
        os_, arch, variant = platform
        for entry in manifest["manifests"]:
            p = entry.get("platform", {})
            if (p.get("os"), p.get("architecture")) == (os_, arch) and \
                    (not variant or not p.get("variant") or p.get("variant") == variant):
                manifest = json.loads(registry_get(registry, repo, "manifests", entry["digest"], ACCEPT_MANIFEST))
                break
        else:
            raise Abgelehnt(f"{repo}@{digest}: keine Variante für {platform}")
    return json.loads(blob(registry, repo, manifest["config"]["digest"]))


def parse_reference(ref):
    """Zerlegt eine Image-Referenz mit Digest in Registry, Repository und Digest."""
    if "@" not in ref:
        raise Abgelehnt(f"Referenz ohne Digest: {ref}")
    name, digest = ref.split("@", 1)
    first, _, rest = name.partition("/")
    if rest and ("." in first or ":" in first or first == "localhost"):
        registry, repo = first, rest
    else:
        registry, repo = "docker.io", name
        if "/" not in repo:
            repo = "library/" + repo
    repo = re.sub(r":[^/]+$", "", repo)               # optionaler Tag vor dem Digest
    return registry, repo, digest


# ------------------------------------------------------------------- Prüfung

def load_provenance(image, tks, work):
    """Voraussetzung: Herkunftsnachweis mit gültiger Signatur der Build-Plattform."""
    key = os.path.join(work, "build_platform.pub")
    with open(key, "w") as f:
        f.write(tks["build_platform.pub"])
    res = run(["cosign", "verify-attestation", "--key", key, "--type", SLSA_TYPE,
               "--insecure-ignore-tlog=true", "--allow-insecure-registry", "--allow-http-registry", image])
    if res.returncode != 0:
        raise Abgelehnt("kein gültig signierter Herkunftsnachweis der Build-Plattform")
    statement = json.loads(base64.b64decode(json.loads(res.stdout.splitlines()[0])["payload"]))
    digest = image.split("@", 1)[1].split(":", 1)[1]
    if digest not in [s.get("digest", {}).get("sha256") for s in statement.get("subject", [])]:
        raise Abgelehnt("Herkunftsnachweis gehört nicht zum Image")
    if statement["predicate"]["runDetails"]["builder"]["id"] != EXPECTED_BUILDER:
        raise Abgelehnt("unerwartete builder.id")
    return statement["predicate"]


def byproduct(predicate, suffix):
    found = [b for b in predicate.get("runDetails", {}).get("byproducts", []) if b.get("name", "").endswith(suffix)]
    if len(found) != 1:
        raise Abgelehnt(f"{suffix.strip('/')} nicht eindeutig im Herkunftsnachweis")
    return json.loads(base64.b64decode(found[0]["content"]))


def check_authorization(predicate, tks, work):
    """Schritt 2: das Tag-Objekt der Freigabe ist vom Authorizer signiert und nennt den Commit."""
    params = predicate["buildDefinition"]["externalParameters"]["runSpec"]["params"]
    rev = next((p["value"] for p in params if p.get("name") == "revision"), "")
    if not re.fullmatch(r"[0-9a-f]{40}", rev):
        raise Abgelehnt("Build-Auftrag nennt keinen Commit-Hash")
    tag = byproduct(predicate, "/AUTHORIZATION_TAG")
    if tag.splitlines()[0] != f"object {rev}":
        raise Abgelehnt("Autorisierungsnachweis nennt einen anderen Commit")
    signers = os.path.join(work, "allowed_signers_authorizer")
    with open(signers, "w") as f:
        f.write(tks["allowed_signers_authorizer"])
    repo = os.path.join(work, "tag")
    run(["git", "init", "-q", repo])
    sha = run(["git", "-C", repo, "hash-object", "-t", "tag", "-w", "--stdin"], input=tag).stdout.strip()
    res = run(["git", "-C", repo, "-c", f"gpg.ssh.allowedSignersFile={signers}", "verify-tag", sha])
    if res.returncode != 0:
        raise Abgelehnt("Autorisierungsnachweis ist nicht von einem Authorizer signiert")
    return rev


def load_sbom(predicate, repo):
    """Schritt 4: Stückliste nur über den Digest im Herkunftsnachweis laden."""
    digest = byproduct(predicate, "/SBOM_DIGEST")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Abgelehnt("keine Stückliste im Herkunftsnachweis")
    return json.loads(blob(REGISTRY, repo, digest)), digest


def purl_name_version(purl):
    m = re.fullmatch(r"pkg:([a-z]+)/(.+)@([^@?]+)(\?.*)?", purl.replace("%40", "@").replace("%2B", "+"))
    return (m.group(1), m.group(2), m.group(3)) if m else (None, purl, "")


_base_cache = {}


def check_lockfile(sbom, rev, repo, digest, work):
    """Schritt 5: jede Komponente außerhalb des Basis-Images steht im Lockfile des Commits."""
    src = os.path.join(work, "src.git")
    if run(["git", "clone", "-q", "--bare", VCS_URL, src]).returncode != 0:
        raise Abgelehnt("VCS nicht erreichbar")
    if run(["git", "-C", src, "cat-file", "-e", f"{rev}^{{commit}}"]).returncode != 0:
        raise Abgelehnt(f"Commit {rev} nicht im VCS")
    lock = run(["git", "-C", src, "show", f"{rev}:package-lock.json"])
    dockerfile = run(["git", "-C", src, "show", f"{rev}:Dockerfile"])
    if lock.returncode != 0 or dockerfile.returncode != 0:
        raise Abgelehnt("Lockfile oder Dockerfile fehlt im Commit")
    base_ref = next((l.split()[1] for l in dockerfile.stdout.splitlines()
                     if l.strip().upper().startswith("FROM ")), "")
    config = image_config(REGISTRY, repo, digest)
    platform = (config.get("os"), config.get("architecture"), config.get("variant"))
    key = (base_ref, platform)
    if key not in _base_cache:
        _base_cache[key] = image_config(*parse_reference(base_ref), platform=platform)["rootfs"]["diff_ids"]
    base = _base_cache[key]
    if config["rootfs"]["diff_ids"][:len(base)] != base:
        raise Abgelehnt(f"Image baut nicht auf dem Basis-Image {base_ref} auf")
    app = set()
    for c in sbom.get("components", []):
        if not c.get("purl"):
            continue
        layers = [p["value"] for p in c.get("properties", [])
                  if re.fullmatch(r"syft:location:\d+:layerID", p.get("name", ""))]
        if not layers or any(l not in base for l in layers):
            app.add(c["purl"].split("?")[0].replace("%40", "@"))
    expected = set()
    for path, pkg in json.loads(lock.stdout).get("packages", {}).items():
        name = pkg.get("name") if path == "" else pkg.get("name", path.rsplit("node_modules/", 1)[-1])
        expected.add(f"pkg:npm/{name}@{pkg.get('version')}")
    unexpected = sorted(app - expected)
    if unexpected:
        raise Abgelehnt("Komponenten nicht in der Abhängigkeitsdefinition: " + ", ".join(unexpected[:5])
                        + (f" und {len(unexpected) - 5} weitere" if len(unexpected) > 5 else ""))
    return len(app)


_index_cache = {}
_index_lock = threading.Lock()


def _version(v):
    if v == "0":
        return ((-1, 0, 0, 0), 0, "")
    core, _, pre = v.split("+")[0].partition("-")
    nums = [int(x) if x.isdigit() else 0 for x in core.split(".")][:4]
    return (tuple(nums + [0] * (4 - len(nums))), 0 if pre else 1, pre)


def _affected(entry, version):
    if version in entry.get("versions", []):
        return True
    x = _version(version)
    for events in entry.get("ranges", []):
        for i in (_version(e["introduced"]) for e in events if "introduced" in e):
            fixed = any(i < _version(e["fixed"]) <= x for e in events if "fixed" in e)
            last = any(i <= _version(e["last_affected"]) < x for e in events if "last_affected" in e)
            if i <= x and not fixed and not last:
                return True
    return False


def check_reports(sbom, tks):
    """Schritt 6: keine npm-Komponente ist als bösartig gemeldet."""
    entry = dict(line.split(None, 1) for line in tks.get("malicious_packages", "").splitlines() if line.strip())
    digest = entry.get("digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise Abgelehnt("kein Index der Meldeliste im Trusted Key Store")
    with _index_lock:
        if digest not in _index_cache:
            _index_cache.clear()
            _index_cache[digest] = json.loads(blob(REGISTRY, INDEX_REPO, digest))
        index = _index_cache[digest]
    packages = {purl_name_version(c["purl"])[1:] for c in sbom.get("components", [])
                if c.get("purl", "").startswith("pkg:npm/")}
    hits = [f"{n}@{v} {e['id']}" for n, v in sorted(packages) for e in index.get(n, []) if _affected(e, v)]
    if hits:
        raise Abgelehnt("gemeldete bösartige Komponenten: " + ", ".join(hits))
    return len(packages), entry.get("commit", "")[:12]


def verify_image(image, tks):
    registry, repo, digest = parse_reference(image)
    if registry != REGISTRY:
        raise Abgelehnt(f"Image stammt nicht aus der Registry der Lieferkette: {image}")
    ref = f"{REGISTRY}/{repo}@{digest}"
    with tempfile.TemporaryDirectory() as work:
        predicate = load_provenance(ref, tks, work)
        rev = check_authorization(predicate, tks, work)
        sbom, sbom_digest = load_sbom(predicate, repo)
        n_app = check_lockfile(sbom, rev, repo, digest, work)
        n_npm, mal_commit = check_reports(sbom, tks)
    return (f"Freigabe von {rev[:12]} gültig, Stückliste {sbom_digest[:19]} gebunden, "
            f"{n_app} Komponenten der Anwendung im Lockfile, {n_npm} npm-Pakete ohne Meldung (Stand {mal_commit})")


# ---------------------------------------------------------------------- HTTP

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.reply({"status": "ok"} if self.path == "/healthz" else {"error": "unbekannt"},
                   200 if self.path == "/healthz" else 404)

    def do_POST(self):
        if self.path != "/verify":
            return self.reply({"error": "unbekannt"}, 404)
        try:
            authenticate(self.headers.get("Authorization", ""))
            request = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
            images = request.get("images") or []
            if not images:
                raise Abgelehnt("keine Images in der Anfrage")
            tks = trusted_key_store()
            reasons = [verify_image(image, tks) for image in images]
            result = {"allowed": True, "reason": "; ".join(reasons)}
        except Abgelehnt as err:
            result = {"allowed": False, "reason": str(err)}
        except Exception as err:                          # Ablehnung im Zweifel
            result = {"allowed": False, "reason": f"Prüfung nicht durchführbar: {type(err).__name__}: {err}"}
        log(images=locals().get("images"), **result)
        self.reply(result)

    def reply(self, obj, code=200):
        data = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    log(event="start", registry=REGISTRY, vcs=VCS_URL)
    ThreadingHTTPServer(("", 8080), Handler).serve_forever()
