"""Adversarialer Test: ua-parser-js (2021) — Image an der Build-Plattform vorbei (T4, VG4).

Bildet den ua-parser-js-Vorfall auf den Prototyp ab. Beim Vorfall veroeffentlichte
ein Angreifer mit einem uebernommenen Konto (CAPEC-560, F1) boesartige Versionen
direkt in der Registry. Das Quellcode-Repository blieb unveraendert, und zu den
Versionen gab es weder einen Commit noch einen Tag. Die Pakete stammten also aus
keinem Quellcodestand und nicht von der regulaeren Build-Plattform.

Im Prototyp entspricht das einem Image, das nicht von der Build-Plattform gebaut
wurde und dennoch im Cluster ausgerollt werden soll. Der Angriff umgeht die
Build-Pipeline vollstaendig. Er bringt ein fremdes, hier harmloses Standard-Image
in den geschuetzten Namespace deploy. Die Baseline besitzt keine
Zulassungskontrolle und laesst das Image zu (verletzte Annahme A4). Die gehaertete
Kette verlangt fuer jedes Image einen gueltigen, an den Digest gebundenen
Herkunftsnachweis der Build-Plattform (AN7). Fuer ein fremdes Image existiert kein
solcher Nachweis, die Zulassung wird daher abgelehnt.
"""

import time

import lib

# Harmloses Standard-Image, das nicht aus der Build-Plattform stammt.
FOREIGN_IMAGE = "docker.io/library/busybox:1.36"
POD_NAME = "t4-uaparser"


class UaParserImageBypass(lib.AttackTest):
    META = {
        "id": "uaparser-image-bypass",
        "title": "ua-parser-js — Image an der Build-Plattform vorbei",
        "vg": "VG4 (Build-Plattform -> Distributor)",
        "capec": "CAPEC-560",
        "stride": "Spoofing, Tampering",
        "assumption": "A4",
        "incident": "ua-parser-js, 2021",
    }

    def _pod_manifest(self) -> str:
        ns = self.cfg["deploy_ns"]
        return (
            "apiVersion: v1\n"
            "kind: Pod\n"
            "metadata:\n"
            f"  name: {POD_NAME}\n"
            f"  namespace: {ns}\n"
            "  labels:\n"
            f"    app: {POD_NAME}\n"
            "    adversarial: uaparser-image-bypass\n"
            "spec:\n"
            "  restartPolicy: Never\n"
            "  containers:\n"
            "  - name: app\n"
            f"    image: {FOREIGN_IMAGE}\n"
            "    imagePullPolicy: IfNotPresent\n"
            '    command: ["sh", "-c", "sleep 3600"]\n'
        )

    def attack(self) -> None:
        # Angreifer mit uebernommenem Konto (F1) bringt ein fremdes Image in den
        # geschuetzten Namespace. Es durchlief nie die Build-Pipeline, daher gibt
        # es keinen Herkunftsnachweis.
        self._delete_pod()  # moeglichen Rest eines frueheren Laufs entfernen
        print(f"    -> rolle fremdes Image {FOREIGN_IMAGE} in Namespace {self.cfg['deploy_ns']} aus")
        try:
            lib.run(lib.kubectl(self.cfg, "create", "-f", "-"), input=self._pod_manifest())
        except lib.CommandError as exc:
            # Die Zulassungskontrolle (Kyverno) hat den Pod bei der Aufnahme abgewiesen.
            raise lib.AttackBlocked(f"Zulassung abgelehnt: {self._admission_reason(exc)}") from exc
        # Kein Fehler bei create bedeutet: der Pod wurde zugelassen (keine oder
        # bestandene Zulassungspruefung). Bei failurePolicy Fail ist die Pruefung
        # synchron, eine Ablehnung schlaege hier bereits fehl.
        self._admitted = True
        print("    -> Pod zugelassen (fremdes Image im Cluster aufgenommen)")

    def probe(self) -> bool:
        # Die Zulassung ist bereits entschieden. Hier wird der zugelassene Pod nur
        # noch kurz beobachtet, um seinen Zustand in die Meldung aufzunehmen.
        admitted = getattr(self, "_admitted", False)
        phase = self._wait_phase() if admitted else ""
        if admitted:
            self.detail = (
                f"Fremdes Image {FOREIGN_IMAGE} ohne Herkunftsnachweis zugelassen "
                f"(Namespace {self.cfg['deploy_ns']}, Phase {phase or 'unbekannt'})"
            )
        else:
            self.detail = "Pod nicht zugelassen"
        return admitted

    def cleanup(self) -> None:
        self._delete_pod()
        print(f"    -> Pod {POD_NAME} entfernt")

    # ---- Helfer ----------------------------------------------------------- #
    def _wait_phase(self, timeout: int = 40) -> str:
        """Pollt die Pod-Phase, bis Running erreicht ist oder der Timeout greift.
        Dient nur der Meldung, nicht der Bewertung."""
        deadline = time.time() + timeout
        phase = ""
        while time.time() < deadline:
            phase = self._pod_phase()
            if phase in ("Running", "Succeeded", "Failed"):
                return phase
            time.sleep(2)
        return phase

    def _pod_phase(self) -> str:
        return lib.run(
            lib.kubectl(self.cfg, "get", "pod", POD_NAME, "-n", self.cfg["deploy_ns"],
                        "-o", "jsonpath={.status.phase}"),
            check=False,
        ).stdout.strip()

    def _delete_pod(self) -> None:
        lib.run(
            lib.kubectl(self.cfg, "delete", "pod", POD_NAME, "-n", self.cfg["deploy_ns"],
                        "--ignore-not-found", "--wait=false"),
            check=False,
        )

    @staticmethod
    def _admission_reason(exc: lib.CommandError) -> str:
        """Kurze Begruendung aus der Fehlermeldung der Zulassungskontrolle."""
        text = (exc.stderr or exc.stdout or "").strip()
        for marker in ("admission webhook", "Pruefdienst", "Prüfdienst", "verifyImages", "policies"):
            idx = text.find(marker)
            if idx != -1:
                return " ".join(text[idx:idx + 300].split())
        lines = text.splitlines()
        return (lines[-1][:200] if lines else "") or str(exc)
