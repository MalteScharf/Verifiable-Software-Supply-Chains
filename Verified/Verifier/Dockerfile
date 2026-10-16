# Prüfdienst der Zulassungskontrolle (AN7): Python-Standardbibliothek sowie
# cosign (Herkunftsnachweis), git und ssh-keygen (Freigabe). Basis-Images per Digest.
FROM ghcr.io/sigstore/cosign/cosign:v3.1.3@sha256:9e5c2f2edc34351160407ca3416c61855bdf9403c3c5936e0f0be7fc261611b8 AS cosign

FROM python:3.13-alpine@sha256:2d9aefe2fef018a7eb2c13064c89c71929800fd2e5dccdbf52ea5da5bb8d929a
RUN apk add --no-cache git openssh-keygen
COPY --from=cosign /ko-app/cosign /usr/local/bin/cosign
COPY pruefdienst.py /app/pruefdienst.py
USER 65534:65534
ENV HOME=/tmp PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
EXPOSE 8080
ENTRYPOINT ["python", "/app/pruefdienst.py"]
