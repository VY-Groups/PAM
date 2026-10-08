# DEV-ONLY image for the VY-PAM phase-2 license server.
#
# Docker is a development convenience (see docker-compose.yml): it exists for
# runtime and real-time testing only. Neither VY-PAM MASTER nor the shipped
# VY-PAM require a container runtime in production - both install directly on
# their target systems (docs/DEPLOYMENT_RUNBOOK.md).
#
# Build context is the REPO ROOT:
#   docker build -f backend/phase2_license_server/Dockerfile -t vypam-license-server:dev .
# or just:  docker compose -f backend/phase2_license_server/docker-compose.yml up --build
FROM python:3.14-slim

WORKDIR /app

COPY backend/phase2_license_server/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# The application in its real layout: licensing_bridge hard-requires the
# Phase 1 crypto engine next door, and config resolves key paths against the
# repo root (backend/phase2_license_server -> ../..).
COPY backend/ipam_licensing /app/backend/ipam_licensing
COPY backend/phase2_license_server /app/backend/phase2_license_server
# Contract + UI test inputs: the suites read apis/openapi.yaml and the
# screen files from the repo root, exactly like on the host.
COPY apis /app/apis
COPY frontend /app/frontend

WORKDIR /app/backend/phase2_license_server

# Dev signing keys are created inside the image: the repository refuses to
# track private key material (contract suite), and .dockerignore keeps any
# local key files out of the build context. The public counterparts and the
# vault key derive at first boot.
RUN python -c "from licensing_bridge import LicenseGenerator; LicenseGenerator(private_key_path='/app/license_private_key.pem')"

EXPOSE 5000
ENV LICENSE_SERVER_HOST=0.0.0.0
CMD ["python", "app.py"]
