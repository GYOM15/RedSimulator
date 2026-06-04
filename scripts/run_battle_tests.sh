#!/bin/bash
# Run battle tests against Docker targets.
#
# Usage:
#   ./scripts/run_battle_tests.sh          # start targets, run tests, stop targets
#   ./scripts/run_battle_tests.sh --keep   # leave targets running after tests
set -e

COMPOSE_FILE="docker/targets/docker-compose.targets.yml"
KEEP_RUNNING=false

if [[ "$1" == "--keep" ]]; then
    KEEP_RUNNING=true
fi

echo "=== Starting target containers ==="
docker compose -f "$COMPOSE_FILE" up -d

echo "=== Waiting for targets to be healthy ==="
for port in 4280 4281 4282; do
    echo -n "  Waiting for localhost:$port..."
    for i in $(seq 1 30); do
        if curl -sf "http://localhost:$port" > /dev/null 2>&1; then
            echo " ready"
            break
        fi
        if [ "$i" -eq 30 ]; then
            echo " TIMEOUT"
        fi
        sleep 2
    done
done

echo "=== Running battle tests ==="
python -m pytest tests/battle/ -v --tb=short

if [ "$KEEP_RUNNING" = false ]; then
    echo "=== Stopping targets ==="
    docker compose -f "$COMPOSE_FILE" down
else
    echo "=== Targets left running (use 'docker compose -f $COMPOSE_FILE down' to stop) ==="
fi
