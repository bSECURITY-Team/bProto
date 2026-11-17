# Build binaries with the locked project commands before building this image.
# Trixie supplies glibc >= 2.41, compatible with this development executor.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 openssl iproute2 iputils-ping ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Compose mounts only the required fixtures and stripped binaries read-only.
# Keeping changing binaries out of image layers also bounds VFS cache growth.
ENV BPROTO_TEST_BIN_DIR=/usr/local/bin BPROTO_TEST_PANEL_BIN=/usr/local/bin/panel
ENTRYPOINT ["python3", "tools/key-sync-lab/runner.py"]
