#!/bin/bash

set -e

# Configuration
IMAGE_NAME="dss-validator"
CONTAINER_NAME="dss-validator"
PORT=8080

# Detect container tool
if command -v container >/dev/null 2>&1; then
    TOOL="container"
    echo "✅ Found Apple's native 'container' CLI. Using it for local setup."
elif command -v docker >/dev/null 2>&1; then
    TOOL="docker"
    echo "ℹ️ Apple 'container' CLI not found. Falling back to 'docker'."
else
    echo "❌ Error: Neither 'container' nor 'docker' found in PATH."
    exit 1
fi

# Build the image
echo "🔨 Building $IMAGE_NAME image using $TOOL..."
DOCKERFILE="testfiles/dss/Dockerfile.dss"
CONTEXT="testfiles/dss"

if [ "$TOOL" == "container" ]; then
    if ! container build --cpus 6 --memory 10g -t "$IMAGE_NAME" -f "$DOCKERFILE" "$CONTEXT"; then
        BUILD_ERR=$?
        if container build --cpus 6 --memory 10g -t "$IMAGE_NAME" -f "$DOCKERFILE" "$CONTEXT" 2>&1 | grep -q "Rosetta is not installed"; then
            echo ""
            echo "❌ Error: Rosetta 2 is not installed. This is required for Apple's 'container' CLI."
            echo "💡 Tip: You can install it by running:"
            echo "   softwareupdate --install-rosetta --agree-to-license"
            echo ""
        fi
        exit $BUILD_ERR
    fi
else
    docker build -t "$IMAGE_NAME" -f "$DOCKERFILE" "$CONTEXT"
fi

# Stop existing container if running
echo "🛑 Stopping existing $CONTAINER_NAME container if it exists..."
if [ "$TOOL" == "container" ]; then
    container stop "$CONTAINER_NAME" 2>/dev/null || true
    container rm "$CONTAINER_NAME" 2>/dev/null || true
else
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# Start the container
echo "🚀 Starting $CONTAINER_NAME on port $PORT (4 CPUs, 4GB RAM)..."
if [ "$TOOL" == "container" ]; then
    # Apple's 'container' tool uses -p for publishing ports
    container run --name "$CONTAINER_NAME" --detach --rm -p $PORT:8080 -c 4 -m 4g "$IMAGE_NAME"
else
    # Docker uses -d for detach and -p for port
    docker run --name "$CONTAINER_NAME" -d -p $PORT:8080 --cpus 4 --memory 4g "$IMAGE_NAME"
fi

echo "⏳ Waiting for DSS Service to be ready (this may take a minute)..."
COUNT=0
# Check both v1 and v2 endpoints for health
until curl -s --connect-timeout 5 --max-time 10 http://localhost:8080/services/rest/validation/validateSignature -X POST -H "Content-Type: application/json" -d '{"signedDocument":{"bytes":"","name":""}}' | grep -q "simpleReport" 2>/dev/null || \
      curl -s --connect-timeout 5 --max-time 10 http://localhost:8080/services/rest/validation/v2/validateSignature -X POST -H "Content-Type: application/json" -d '{"signedDocument":{"bytes":"","name":""}}' | grep -q "simpleReport" 2>/dev/null; do
    
    # Check if container is still running
    if ! $TOOL inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null | grep -q "true"; then
        echo "❌ Error: Container $CONTAINER_NAME stopped unexpectedly."
        $TOOL logs "$CONTAINER_NAME"
        exit 1
    fi

    # Periodically show the last few lines of logs to see progress in GHA
    if [ $((COUNT % 3)) -eq 0 ] && [ $COUNT -gt 0 ]; then
        echo "   📋 Latest logs:"
        $TOOL logs --tail 2 "$CONTAINER_NAME" | sed 's/^/      /'
    fi

    # Verify port mapping is active
    if ! $TOOL port "$CONTAINER_NAME" 8080 >/dev/null 2>&1; then
        echo "   ⚠️  Warning: Port 8080 is not yet mapped for $CONTAINER_NAME"
    fi

    COUNT=$((COUNT+1))
    echo "   [Attempt $COUNT] Still waiting..."
    sleep 5
    if [ $COUNT -gt 60 ]; then
        echo "❌ Error: DSS Service failed to start within 5 minutes."
        echo "📋 DSS Container Logs:"
        $TOOL logs "$CONTAINER_NAME"
        echo ""
        echo "� Container Status:"
        $TOOL inspect "$CONTAINER_NAME"
        exit 1
    fi
done

echo "✅ DSS Service is ready at http://localhost:8080/services/rest"
echo "👉 You can now run: DSS_API_URL=http://localhost:8080/services/rest/validation/validateSignature go test -v ./sign -run TestValidateDSSValidation"
