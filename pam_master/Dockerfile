# DEV-ONLY image for VY-PAM MASTER.
#
# Docker is a development convenience (see pam_master/docker-compose.yml).
# Neither VY-PAM MASTER nor the shipped VY-PAM require a container runtime in
# production — both install directly on their target systems.
#
# Build context is the REPO ROOT (docker compose sets this): the vendor tool
# needs the shared crypto engine from backend/ipam_licensing.
FROM python:3.12-slim

WORKDIR /app

COPY pam_master/requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Shared crypto engine: signing and verification live in one library so the
# two products can never drift apart.
COPY backend/ipam_licensing /app/backend/ipam_licensing
# Vendor tool project folder (package lives inside it).
COPY pam_master /app/pam_master

WORKDIR /app/pam_master
EXPOSE 5400
CMD ["python", "-m", "pam_master"]
