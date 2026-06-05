#!/bin/bash
set -e -x -o pipefail

REPO=github.com/obot-platform/enterprise-providers
REPO_DIR=/obot-providers/enterprise-providers
REPO_NAME=$(basename $REPO)

if [[ -x "${REPO_DIR}/scripts/build.sh" ]]; then
    (
        echo "Running build script for ${REPO}..."
        cd "${REPO_DIR}"
        ./scripts/build.sh
        echo "Build script for ${REPO} complete!"
    )
else
    echo "No build script found in ${REPO}"
fi

OBOT_SERVER_VERSIONS="$(
    cat <<VERSIONS
${REPO}=$(cd /obot-providers/enterprise-providers && git rev-parse --short HEAD)
VERSIONS
)"

cd /obot-providers
cat <<EOF >.envrc.providers.enterprise
export OBOT_SERVER_PROVIDER_REGISTRIES="/obot-providers/enterprise-providers"
export OBOT_SERVER_VERSIONS="${OBOT_SERVER_VERSIONS}"
EOF
