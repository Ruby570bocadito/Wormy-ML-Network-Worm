#!/bin/bash
set -e

LAB_DIR="$(cd "$(dirname "$0")" && pwd)"
LAB_COMPOSE="$LAB_DIR/docker-compose-lab.yml"
MAX_ITERATIONS=10
iteration=1

echo "============================================"
echo " Wormy ML Network Worm - Lab Runner v1.0"
echo "============================================"
echo ""

# ── Step 1: Start lab containers ──────────────────────────────────
start_lab() {
    echo "[*] Starting lab containers..."
    if ! docker compose -f "$LAB_COMPOSE" up -d; then
        echo "[!] Docker Compose failed. Is Docker running?"
        exit 1
    fi
    echo "[+] Lab containers started"
    echo "[*] Waiting for services to be ready..."
    sleep 15
}

# ── Step 2: Build worm container ──────────────────────────────────
build_worm() {
    echo "[*] Building worm image..."
    docker build -t wormy:latest "$LAB_DIR" 2>&1 | tail -3
    echo "[+] Worm image built"
}

# ── Step 3: Run worm propagation ──────────────────────────────────
run_worm() {
    local iteration=$1
    local logfile="$LAB_DIR/logs/run_${iteration}.log"

    echo "[*] Run #${iteration}: Starting worm propagation..."

    docker rm -f wormy-runner 2>/dev/null || true

    docker run --rm \
        --name wormy-runner \
        --network "$(docker compose -f "$LAB_COMPOSE" ps -q redis 2>/dev/null | xargs docker inspect -f '{{range $net, $v := .NetworkSettings.Networks}}{{$net}}{{end}}' 2>/dev/null || echo "wormy-ml-network-worm-main_lab_network")" \
        -v "$LAB_DIR/logs:/opt/wormy/logs" \
        wormy:latest \
        python3 worm_core.py --config config_lab.yaml --profile lab_docker 2>&1 | tee "$logfile"

    echo "[+] Run #${iteration} complete (log: $logfile)"
}

# ── Step 4: Count infections from log ──────────────────────────────
count_infections() {
    local logfile="$1"
    grep -cP "Infected\s+" "$logfile" 2>/dev/null || echo 0
}

list_infected() {
    local logfile="$1"
    grep -oP 'Infected \K[\d.]+' "$logfile" 2>/dev/null || true
}

check_all_infected() {
    local logfile="$1"
    local infected=$(list_infected "$logfile" | sort -u | wc -l)
    local total=$(docker compose -f "$LAB_COMPOSE" ps --services 2>/dev/null | wc -l)
    echo "$infected/$total hosts infected"
    if [ "$infected" -ge "$total" ]; then
        return 0
    fi
    return 1
}

# ── Main Loop ─────────────────────────────────────────────────────
start_lab
build_worm

while [ $iteration -le $MAX_ITERATIONS ]; do
    echo ""
    echo "============================================"
    echo " ITERATION $iteration of $MAX_ITERATIONS"
    echo "============================================"

    run_worm "$iteration"

    INFECTED=$(count_infections "$LAB_DIR/logs/run_${iteration}.log")
    TOTAL=$(docker compose -f "$LAB_COMPOSE" ps --services 2>/dev/null | wc -l)

    echo ""
    echo "[!] Run #${iteration}: $INFECTED hosts infected"
    echo "[!] Infected:"
    list_infected "$LAB_DIR/logs/run_${iteration}.log" | sort -u

    if check_all_infected "$LAB_DIR/logs/run_${iteration}.log"; then
        echo ""
        echo "============================================"
        echo " SUCCESS: All hosts infected!"
        echo "============================================"
        exit 0
    fi

    echo ""
    echo "[!] Not all hosts infected yet."
    echo "[!] Check logs/run_${iteration}.log for details."
    echo "[!] Iterating... ($((MAX_ITERATIONS - iteration)) remaining)"

    iteration=$((iteration + 1))
    sleep 2
done

echo ""
echo "============================================"
echo " FAILED after $MAX_ITERATIONS iterations"
echo "============================================"
echo "Check logs/ directory for details."
exit 1
