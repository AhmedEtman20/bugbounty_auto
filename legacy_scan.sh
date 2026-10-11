#!/usr/bin/env bash
# ============================================================
#  Legacy Hunter v4 — Ultimate Edition
#  مبادئ التصميم:
#   1. NEVER exit on error (مفيش set -e)
#   2. Time budget لكل مرحلة (4.5 ساعة كحد أقصى)
#   3. Tool checks قبل الاستخدام
#   4. Parallel execution حيث ممكن
#   5. Progress saving في كل مرحلة
# ============================================================

# ⚠️ مهم: مش بنستخدم set -e عشان ميقفلش
set -u
IFS=$'\n\t'

# ─── Colors ───
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'
PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

hdr()  { echo -e "\n${PURPLE}${BOLD}═══ $1 ═══${NC}"; }
ok()   { echo -e "${GREEN}  [+]${NC} $1"; }
warn() { echo -e "${YELLOW}  [!]${NC} $1"; }
err()  { echo -e "${RED}  [-]${NC} $1"; }
info() { echo -e "${CYAN}  [i]${NC} $1"; }
cnt()  { wc -l < "$1" 2>/dev/null | tr -d ' ' || echo 0; }

# ═══════════════════════════════════════════════════════════
#  TIME BUDGET — 4.5 ساعة كحد أقصى
# ═══════════════════════════════════════════════════════════
MAX_RUNTIME_SEC=16200   # 4h 30m
BATCH_START=$(date +%s)

time_left() {
    local now; now=$(date +%s)
    echo $(( MAX_RUNTIME_SEC - (now - BATCH_START) ))
}
time_left_h() {
    echo "$(( $(time_left) / 60 ))m"
}
has_time() {
    [ "$(time_left)" -gt "${1:-300}" ]
}

# ═══════════════════════════════════════════════════════════
#  TOOL CHECKS — قبل أي استخدام
# ═══════════════════════════════════════════════════════════
HAS() { command -v "$1" >/dev/null 2>&1; }

verify_tools() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}${BOLD}║  Tool Verification                               ║${NC}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
    MISSING=()
    for tool in subfinder assetfinder httpx katana nuclei gau waybackurls dalfox sqlmap jq curl subjs getJS jsluice; do
        if HAS "$tool"; then
            printf "  ${GREEN}✓${NC} %-20s\n" "$tool"
        else
            printf "  ${RED}✗${NC} %-20s\n" "$tool"
            MISSING+=("$tool")
        fi
    done
    # Optional tools
    echo "  --- Optional ---"
    for tool in amass robofinder paramspider arjun nikto commix interactsh-client jaeles gf; do
        if HAS "$tool" || [ -f "/opt/commix/commix.py" ]; then
            printf "  ${GREEN}✓${NC} %-20s\n" "$tool"
        else
            printf "  ${YELLOW}○${NC} %-20s (optional)\n" "$tool"
        fi
    done
    if [ ${#MISSING[@]} -gt 0 ]; then
        warn "Missing critical tools: ${MISSING[*]}"
        warn "Some phases will be SKIPPED."
    fi
    echo ""
}

# ═══════════════════════════════════════════════════════════
#  NOTIFICATIONS
# ═══════════════════════════════════════════════════════════
send_slack() {
    [ -z "${SLACK_WEBHOOK_URL:-}" ] && return 0
    curl -s -X POST "$SLACK_WEBHOOK_URL" -H 'Content-type: application/json' \
        --data "{\"text\":\"$1\"}" >/dev/null 2>&1 || true
}
send_discord() {
    [ -z "${DISCORD_WEBHOOK_URL:-}" ] && return 0
    local p
    p=$(python3 -c "import json,sys; print(json.dumps({'content': sys.argv[1]}))" "$1" 2>/dev/null) || return 0
    curl -s -X POST "$DISCORD_WEBHOOK_URL" -H 'Content-type: application/json' \
        --data "$p" >/dev/null 2>&1 || true
}
notify() {
    send_slack "$1"
    send_discord "$1"
    echo -e "${CYAN}  [notify]${NC} $1"
}

create_github_issue() {
    local title="$1"; local body="$2"; local labels="${3:-security,automated}"
    [ -z "${GITHUB_TOKEN:-}" ] && return 0
    [ -z "${GITHUB_REPOSITORY:-}" ] && return 0
    local payload
    payload=$(python3 -c "import json,sys; print(json.dumps({'title': sys.argv[1], 'body': sys.argv[2], 'labels': sys.argv[3].split(',')}))" "$title" "$body" "$labels" 2>/dev/null) || return 0
    curl -s -X POST \
        -H "Authorization: token $GITHUB_TOKEN" \
        -H "Accept: application/vnd.github+json" \
        -d "$payload" \
        "https://api.github.com/repos/${GITHUB_REPOSITORY}/issues" >/dev/null 2>&1 || true
}

# ═══════════════════════════════════════════════════════════
#  CUSTOM NUCLEI TEMPLATES
# ═══════════════════════════════════════════════════════════
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
    path: ["{{BaseURL}}/.env", "{{BaseURL}}/.env.bak", "{{BaseURL}}/backup.zip", "{{BaseURL}}/.git/config", "{{BaseURL}}/.env.production", "{{BaseURL}}/config.php.bak", "{{BaseURL}}/db.sql", "{{BaseURL}}/dump.sql"]
    matchers-condition: or
    matchers:
      - type: word
        words: ["DB_PASSWORD", "DB_USER", "mysql://", "AWS_ACCESS_KEY", "SECRET_KEY", "postgres://"]
YAML_EOF
    cat << 'YAML_EOF' > scripts/nuclei-templates/legacy-api-version.yaml
id: legacy-api-version
info:
  name: Legacy API Version Exposure
  severity: medium
requests:
  - method: GET
    path: ["{{BaseURL}}/api/v1/", "{{BaseURL}}/api/v0/", "{{BaseURL}}/swagger-ui.html", "{{BaseURL}}/api-docs", "{{BaseURL}}/openapi.json"]
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
    path: ["{{BaseURL}}/js/app.js", "{{BaseURL}}/static/js/app.js", "{{BaseURL}}/assets/js/app.js"]
    matchers:
      - type: regex
        regex: ['AKIA[0-9A-Z]{16}', 'AIza[0-9A-Za-z_-]{35}', 'sk_live_[0-9a-zA-Z]{24,}', 'ghp_[a-zA-Z0-9]{36}']
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
    cat << 'YAML_EOF' > scripts/nuclei-templates/legacy-mcp-exposure.yaml
id: legacy-mcp-exposure
info:
  name: MCP Server Exposure
  severity: high
  tags: mcp,ai,exposure
requests:
  - method: GET
    path: ["{{BaseURL}}/mcp", "{{BaseURL}}/mcp/sse", "{{BaseURL}}/mcp/admin", "{{BaseURL}}/api/mcp", "{{BaseURL}}/.well-known/mcp.json"]
    matchers-condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["tools", "capabilities", "jsonrpc", "method"]
        condition: or
YAML_EOF
}

# ═══════════════════════════════════════════════════════════
#  INPUT PARSING
# ═══════════════════════════════════════════════════════════
INPUT="${1:-domains.txt}"
[ ! -f "$INPUT" ] && { err "File not found: $INPUT"; exit 1; }

DOMAINS=()
while IFS= read -r line; do
    line=$(echo "$line" | tr -d '\r' | xargs)
    [[ -z "$line" || "$line" =~ ^# ]] && continue
    DOMAINS+=("$line")
done < "$INPUT"

[ ${#DOMAINS[@]} -eq 0 ] && { err "No domains found in $INPUT"; exit 1; }

# ═══════════════════════════════════════════════════════════
#  SETUP
# ═══════════════════════════════════════════════════════════
setup_templates

ROOT="legacy_hunt_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$ROOT"
MASTER_STATS="$ROOT/.stats.txt"
> "$MASTER_STATS"

export PATH="$PATH:$HOME/go/bin:${GOPATH:-$HOME/go}/bin:/usr/local/bin:/opt/commix"

UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
CUSTOM_NUCLEI_DIR="$(pwd)/scripts/nuclei-templates"

echo ""
echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}${BOLD}║  🕰️  LEGACY HUNTER v4 — Ultimate Edition                 ║${NC}"
echo -e "${CYAN}${BOLD}║  Domains   : ${#DOMAINS[@]}                                          ║${NC}"
echo -e "${CYAN}${BOLD}║  Max Time  : 4h 30m                                       ║${NC}"
echo -e "${CYAN}${BOLD}║  Started   : $(date '+%Y-%m-%d %H:%M:%S')                          ║${NC}"
echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
for i in "${!DOMAINS[@]}"; do
    echo "  $((i+1)). ${DOMAINS[$i]}"
done
echo ""

verify_tools

# ═══════════════════════════════════════════════════════════
#  PROCESS SINGLE DOMAIN
# ═══════════════════════════════════════════════════════════
process_domain() {
    local TARGET="$1"; local W="$2"
    TARGET=$(echo "$TARGET" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')

    # كل الفولدرات
    mkdir -p "$W"/{recon,vulns,nuclei,dalfox,sqlmap,commix,jaeles,legacy,js,backups,params,robots,blind_xss,waf}

    # ملفات فارغة لتجنب أخطاء cnt
    touch "$W/recon/subdomains.txt" "$W/recon/live.txt" \
          "$W/legacy/historical_urls.txt" "$W/legacy/all_urls.txt" "$W/legacy/live_urls.txt" \
          "$W/backups/sensitive_files.txt" "$W/params/urls_with_params.txt" \
          "$W/params/old_params.txt" "$W/js/js_endpoints.txt" "$W/js/js_secrets.txt" \
          "$W/nuclei/all_findings.txt" "$W/dalfox/findings.txt" \
          "$W/sqlmap/findings.txt" "$W/commix/findings.txt" \
          "$W/vulns/nikto.txt" "$W/jaeles/findings.txt" "$W/blind_xss/interactions.txt" \
          "$W/vulns/unauth_access.txt" "$W/waf/detected.txt"

    echo ""
    echo -e "${PURPLE}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${PURPLE}${BOLD}║  TARGET: $TARGET${NC}"
    echo -e "${PURPLE}${BOLD}║  Time left in batch: $(time_left_h)${NC}"
    echo -e "${PURPLE}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"

    local T0; T0=$(date +%s)
    notify "🕰️ Starting Legacy Hunt v4 on *$TARGET* (time: $(time_left_h))"

    # ═══════════════════════════════════════════════════════
    #  PHASE 1 — Subdomain Enumeration
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 1/11 — Subdomain Enumeration [$(time_left_h) left]"
    if has_time 600; then
        (
            HAS subfinder && timeout 120 subfinder -d "$TARGET" -all -recursive -silent 2>/dev/null
            HAS assetfinder && timeout 60 assetfinder --subs-only "$TARGET" 2>/dev/null
            timeout 30 curl -s --max-time 25 "https://crt.sh/?q=%25.$TARGET&output=json" 2>/dev/null | jq -r '.[].name_value' 2>/dev/null | sed 's/\*\.//g'
            HAS amass && has_time 1800 && timeout 180 amass enum -passive -d "$TARGET" -silent 2>/dev/null
        ) | sed 's/^\*\.//g' | tr '[:upper:]' '[:lower:]' \
          | grep -E "\.$TARGET$|^$TARGET$" | sort -u > "$W/recon/subdomains.txt" 2>/dev/null || true
    fi
    SUB_CNT=$(cnt "$W/recon/subdomains.txt")
    ok "Subdomains: $SUB_CNT"

    # Wildcard detection
    RANDOM_SUB="$(head /dev/urandom 2>/dev/null | tr -dc 'a-z0-9' | head -c 12)"
    if [ -n "$RANDOM_SUB" ] && host "${RANDOM_SUB}.${TARGET}" >/dev/null 2>&1; then
        warn "Wildcard DNS detected — using HTTP validation only"
    fi

    # ═══════════════════════════════════════════════════════
    #  PHASE 2 — Live Host Detection
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 2/11 — Live Host Detection [$(time_left_h) left]"
    if HAS httpx && [ -s "$W/recon/subdomains.txt" ] && has_time 600; then
        timeout 600 httpx -l "$W/recon/subdomains.txt" -silent \
            -title -tech-detect -status-code -ip -cname -web-server -location \
            -random-agent -t 150 -timeout 8 -retries 1 -follow-redirects \
            -o "$W/recon/httpx_full.txt" 2>/dev/null || true
        awk '{print $1}' "$W/recon/httpx_full.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$W/recon/live.txt" 2>/dev/null || true
    fi
    if [ ! -s "$W/recon/live.txt" ]; then
        warn "No live hosts — using target root"
        echo "https://$TARGET" > "$W/recon/live.txt"
        echo "http://$TARGET" >> "$W/recon/live.txt"
    fi
    LIVE_CNT=$(cnt "$W/recon/live.txt")
    ok "Live hosts: $LIVE_CNT"

    # WAF Detection
    if [ -s "$W/recon/live.txt" ] && has_time 120; then
        head -5 "$W/recon/live.txt" | while read -r url; do
            [ -z "$url" ] && continue
            waf=$(timeout 6 curl -s -I --max-time 5 -A "$UA" "$url" 2>/dev/null | grep -iE 'cf-ray|cloudflare|akamai|x-sucuri|x-iinfo|imperva|incapsula|fastly' | head -1)
            [ -n "$waf" ] && echo "[WAF] $url → $waf" >> "$W/waf/detected.txt"
        done
        [ -s "$W/waf/detected.txt" ] && warn "WAF detected on some hosts"
    fi

    # ═══════════════════════════════════════════════════════
    #  PHASE 3 — Historical Robots.txt
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 3/11 — Historical Robots.txt [$(time_left_h) left]"
    if HAS robofinder && has_time 900; then
        timeout 180 robofinder -u "$TARGET" -o "$W/robots/robots_history.txt" 2>/dev/null || true
    fi
    ROBOTS_CNT=$(cnt "$W/robots/robots_history.txt")
    if [ -f "$W/robots/robots_history.txt" ]; then
        grep -Ei '^(Disallow|Allow):' "$W/robots/robots_history.txt" 2>/dev/null | awk '{print $2}' | grep -v '^$' | sort -u > "$W/robots/robots_paths.txt" 2>/dev/null || true
    fi
    ok "Robots.txt paths: $ROBOTS_CNT"

    # ═══════════════════════════════════════════════════════
    #  PHASE 4 — Historical URL Mining
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 4/11 — Historical URL Mining [$(time_left_h) left]"
    if has_time 900; then
        (
            HAS gau && timeout 240 gau "$TARGET" --threads 30 --timeout 15 --subs 2>/dev/null
            HAS waybackurls && timeout 180 bash -c "echo '$TARGET' | waybackurls 2>/dev/null"
        ) | grep -E '^https?://' | grep -v '^$' | sort -u > "$W/legacy/historical_urls.txt" 2>/dev/null || true
    fi
    HIST_CNT=$(cnt "$W/legacy/historical_urls.txt")
    ok "Historical URLs: $HIST_CNT"

    grep -Ei '\.(bak|old|backup|zip|tar|gz|rar|7z|sql|db|sqlite|env|config|yml|yaml|json|xml|log|txt|md|swp|swo|orig|save|cache|DS_Store)$' \
        "$W/legacy/historical_urls.txt" > "$W/backups/sensitive_files.txt" 2>/dev/null || true
    ok "Sensitive/backup files: $(cnt "$W/backups/sensitive_files.txt")"

    # ═══════════════════════════════════════════════════════
    #  PHASE 5 — Crawling
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 5/11 — Crawling (Katana) [$(time_left_h) left]"
    if HAS katana && has_time 1200; then
        timeout 900 katana -list "$W/recon/live.txt" -d 3 -jc -kf all -fx -xhr -aff \
            -ef png,jpg,jpeg,gif,css,ico,svg,woff,woff2,ttf,eot,mp4,mp3,pdf,zip,rar \
            -random-agent -silent -timeout 10 -c 50 -p 30 \
            -o "$W/legacy/katana_urls.txt" 2>/dev/null || true
    fi
    cat "$W/legacy/historical_urls.txt" "$W/legacy/katana_urls.txt" 2>/dev/null | grep -E '^https?://' | sort -u > "$W/legacy/all_urls.txt" 2>/dev/null || true
    ok "Total URLs (historical + crawl): $(cnt "$W/legacy/all_urls.txt")"

    # ═══════════════════════════════════════════════════════
    #  PHASE 5.5 — Filter Live URLs (مهم جداً للسرعة)
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 5.5/11 — Filter Live URLs [$(time_left_h) left]"
    if HAS httpx && [ -s "$W/legacy/all_urls.txt" ] && has_time 600; then
        # خد 5000 URL كحد أقصى عشان ميعطلش
        head -5000 "$W/legacy/all_urls.txt" | timeout 600 httpx -silent \
            -mc 200,201,301,302,401,403 -random-agent -t 100 -timeout 5 -retries 0 \
            -o "$W/legacy/live_urls.txt" 2>/dev/null || true
        # لو مفيش نتيجة، خد عينة عشوائية
        if [ ! -s "$W/legacy/live_urls.txt" ]; then
            head -500 "$W/legacy/all_urls.txt" > "$W/legacy/live_urls.txt"
        fi
    else
        head -500 "$W/legacy/all_urls.txt" > "$W/legacy/live_urls.txt" 2>/dev/null || true
    fi
    ok "Live historical URLs: $(cnt "$W/legacy/live_urls.txt")"

    # ═══════════════════════════════════════════════════════
    #  PHASE 6 — Parameters (Arjun + ParamSpider + GF)
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 6/11 — Parameter Mining [$(time_left_h) left]"

    # استخراج parameters من كل URLs
    grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | sort -u > "$W/params/urls_with_params.txt" 2>/dev/null || true
    ok "URLs with params: $(cnt "$W/params/urls_with_params.txt")"

    # Arjun
    if HAS arjun && has_time 900; then
        head -3 "$W/recon/live.txt" | timeout 600 arjun -i - -oT "$W/params/arjun.txt" -m GET,POST -t 10 --stable 2>/dev/null || true
    fi

    # ParamSpider
    if HAS paramspider && has_time 300; then
        timeout 240 paramspider -d "$TARGET" -o "$W/params/paramspider.txt" 2>/dev/null || true
        if [ -f "$W/params/paramspider.txt" ]; then
            cat "$W/params/paramspider.txt" 2>/dev/null | grep -E '^https?://' >> "$W/params/urls_with_params.txt" 2>/dev/null || true
            sort -u "$W/params/urls_with_params.txt" -o "$W/params/urls_with_params.txt" 2>/dev/null || true
        fi
    fi

    # GF Patterns
    if HAS gf && has_time 300; then
        for p in xss sqli ssrf lfi rce redirect idor ssti; do
            gf "$p" < "$W/legacy/all_urls.txt" > "$W/params/gf_${p}.txt" 2>/dev/null || true
        done
        info "GF patterns: xss=$(cnt "$W/params/gf_xss.txt") sqli=$(cnt "$W/params/gf_sqli.txt")"
    fi

    # ═══════════════════════════════════════════════════════
    #  PHASE 7 — JS Analysis
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 7/11 — JS Analysis [$(time_left_h) left]"
    grep -E '\.js(\?|$)' "$W/legacy/all_urls.txt" 2>/dev/null | sed 's/?.*$//' | sort -u > "$W/js/js_urls.txt" 2>/dev/null || true

    if HAS subjs && has_time 300; then
        cat "$W/recon/live.txt" | timeout 240 subjs 2>/dev/null | grep -E '\.js(\?|$)' | sed 's/?.*$//' | sort -u >> "$W/js/js_urls.txt" 2>/dev/null || true
    fi
    if HAS getJS && has_time 300; then
        cat "$W/recon/live.txt" | timeout 240 getJS --complete 2>/dev/null | grep -E '\.js(\?|$)' | sed 's/?.*$//' | sort -u >> "$W/js/js_urls.txt" 2>/dev/null || true
    fi

    sort -u "$W/js/js_urls.txt" -o "$W/js/js_urls.txt" 2>/dev/null || true
    ok "JS URLs: $(cnt "$W/js/js_urls.txt")"

    if [ -s "$W/js/js_urls.txt" ] && has_time 900; then
        mkdir -p "$W/js/files"
        head -80 "$W/js/js_urls.txt" | timeout 600 xargs -P 20 -I{} bash -c '
            url="{}"
            f=$(echo "$url" | md5sum | cut -c1-16)
            timeout 10 curl -s --max-time 8 -A "'"$UA"'" "$url" -o "'"$W/js/files"'/$f.js" 2>/dev/null || true
        ' 2>/dev/null || true

        # استخراج endpoints
        if HAS jsluice; then
            find "$W/js/files" -name "*.js" -size +100c 2>/dev/null | while read f; do
                timeout 10 jsluice urls "$f" 2>/dev/null
            done | jq -r 'select(.url) | .url' 2>/dev/null | sort -u > "$W/js/js_endpoints.txt" 2>/dev/null || true
        fi
        ok "JS endpoints: $(cnt "$W/js/js_endpoints.txt")"

        # Secrets
        cat "$W/js/files"/*.js 2>/dev/null | grep -Eo \
            'AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24,}|ghp_[a-zA-Z0-9]{36}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----' \
            | sort -u > "$W/js/js_secrets.txt" 2>/dev/null || true
        ok "Secrets in JS: $(cnt "$W/js/js_secrets.txt")"
    fi

    # ═══════════════════════════════════════════════════════
    #  PHASE 8 — Nuclei (الأهم)
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 8/11 — Nuclei Scans [$(time_left_h) left]"
    NUCLEI_CNT=0

    if HAS nuclei && has_time 1800; then
        # تحديث templates (مرة واحدة)
        timeout 120 nuclei -update-templates -silent 2>/dev/null || true

        # Custom templates
        if [ -d "$CUSTOM_NUCLEI_DIR" ]; then
            timeout 400 nuclei -l "$W/recon/live.txt" -t "$CUSTOM_NUCLEI_DIR" \
                -severity critical,high,medium -rl 100 -c 40 -timeout 10 \
                -random-agent -silent -o "$W/nuclei/custom.txt" 2>/dev/null || true
        fi

        # Full Nuclei على live hosts
        timeout 1200 nuclei -l "$W/recon/live.txt" \
            -severity critical,high,medium \
            -t http/cves/ -t http/vulnerabilities/ -t http/exposures/ \
            -t http/misconfiguration/ -t http/default-logins/ -t http/takeovers/ \
            -rl 200 -c 60 -bs 60 -timeout 8 -retries 1 \
            -random-agent -no-interactsh \
            -o "$W/nuclei/all_findings.txt" 2>/dev/null || true

        # Nuclei على الروابط الحية من الأرشيف (لو فيه وقت)
        if has_time 900; then
            timeout 800 nuclei -l "$W/legacy/live_urls.txt" \
                -severity critical,high \
                -t http/cves/ -t http/vulnerabilities/ -t http/exposures/ \
                -rl 150 -c 50 -timeout 8 \
                -random-agent -no-interactsh \
                -o "$W/nuclei/historical_findings.txt" 2>/dev/null || true
        fi

        cat "$W/nuclei/"*.txt 2>/dev/null | sort -u > "$W/nuclei/merged.txt" 2>/dev/null || true
        NUCLEI_CNT=$(grep -cE '^\[' "$W/nuclei/merged.txt" 2>/dev/null || echo 0)
    fi
    ok "Nuclei findings: $NUCLEI_CNT"

    if [ "$NUCLEI_CNT" -gt 0 ]; then
        CRITICAL_LINES=$(grep -iE '\[critical\]|\[high\]' "$W/nuclei/merged.txt" 2>/dev/null | head -5)
        if [ -n "$CRITICAL_LINES" ]; then
            notify "🔴 *Nuclei Critical/High* on $TARGET — $NUCLEI_CNT"
            create_github_issue "🔴 Nuclei Critical/High — $TARGET" \
                "## Nuclei Findings\n\n**Target:** $TARGET\n**Total:** $NUCLEI_CNT\n\n\`\`\`\n$CRITICAL_LINES\n\`\`\`" \
                "security,nuclei,automated"
        fi
    fi

    # ═══════════════════════════════════════════════════════
    #  PHASE 9 — Unauthenticated Access Check
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 9/11 — Unauthenticated Access Check [$(time_left_h) left]"
    UNAUTH_CNT=0
    if has_time 300; then
        for path in /admin /dashboard /api/admin /swagger-ui.html /actuator /actuator/env /debug /phpinfo.php /.env /.git/config; do
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                [ "$(time_left)" -lt 120 ] && break
                code=$(timeout 5 curl -s -o /dev/null -w "%{http_code}" --max-time 4 -A "$UA" "${url}${path}" 2>/dev/null || echo "000")
                if [ "$code" = "200" ]; then
                    echo "[UNAUTH-200] ${url}${path}" >> "$W/vulns/unauth_access.txt"
                    UNAUTH_CNT=$((UNAUTH_CNT+1))
                fi
            done < <(head -3 "$W/recon/live.txt")
        done
    fi
    ok "Unauthenticated 200 responses: $UNAUTH_CNT"

    # ═══════════════════════════════════════════════════════
    #  PHASE 10 — Active Scanners (Dalfox, SQLMap, Commix, Nikto, Jaeles)
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 10/11 — Active Scanners [$(time_left_h) left]"

    # ── Dalfox (XSS) ──
    DALFOX_CNT=0
    if HAS dalfox && has_time 1200; then
        # استخدم gf_xss لو موجود، وإلا استخدم urls_with_params
        if [ -s "$W/params/gf_xss.txt" ]; then
            head -150 "$W/params/gf_xss.txt" > "$W/dalfox/targets.txt"
        else
            grep '=' "$W/legacy/all_urls.txt" 2>/dev/null | head -100 > "$W/dalfox/targets.txt" 2>/dev/null || true
        fi
        if [ -s "$W/dalfox/targets.txt" ]; then
            timeout 900 dalfox file "$W/dalfox/targets.txt" \
                --deep-domxss --mining-dom --mining-dict --waf-evasion --skip-bav \
                --worker 100 --delay 0 --timeout 12 --retry 1 --output-all --no-color \
                -o "$W/dalfox/findings.txt" --silence 2>/dev/null || true
            DALFOX_CNT=$(grep -ciE '\[V\]|POC|VULN' "$W/dalfox/findings.txt" 2>/dev/null || echo 0)
        fi
    fi
    ok "Dalfox XSS: $DALFOX_CNT"
    if [ "$DALFOX_CNT" -gt 0 ]; then
        notify "🟡 *Dalfox XSS* on $TARGET — $DALFOX_CNT"
        create_github_issue "🟡 XSS Findings — $TARGET" \
            "## XSS\n\n**Target:** $TARGET\n**Findings:** $DALFOX_CNT\n\n\`\`\`\n$(grep -iE '\[V\]|POC' "$W/dalfox/findings.txt" | head -20)\n\`\`\`" \
            "security,xss,automated"
    fi

    # ── SQLMap ──
    SQLMAP_CNT=0
    if HAS sqlmap && has_time 900; then
        # استخدم gf_sqli لو موجود
        if [ -s "$W/params/gf_sqli.txt" ]; then
            head -8 "$W/params/gf_sqli.txt" > "$W/sqlmap/targets.txt"
        else
            head -8 "$W/params/urls_with_params.txt" > "$W/sqlmap/targets.txt" 2>/dev/null || true
        fi
        if [ -s "$W/sqlmap/targets.txt" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                [ "$(time_left)" -lt 300 ] && break
                timeout 90 sqlmap -u "$url" --batch --random-agent \
                    --level=2 --risk=1 --threads=5 --timeout=8 --retries=0 \
                    --technique=BEUSTQ --smart \
                    --output-dir="$W/sqlmap/" --flush-session 2>/dev/null | \
                    grep -iE 'parameter|injectable|vulnerable|Type:|Title:' >> "$W/sqlmap/findings.txt" 2>/dev/null || true
            done < "$W/sqlmap/targets.txt"
            SQLMAP_CNT=$(grep -ci 'injectable' "$W/sqlmap/findings.txt" 2>/dev/null || echo 0)
        fi
    fi
    ok "SQLMap SQLi: $SQLMAP_CNT"
    if [ "$SQLMAP_CNT" -gt 0 ]; then
        notify "🔵 *SQL Injection* on $TARGET — $SQLMAP_CNT"
        create_github_issue "🔵 SQL Injection — $TARGET" \
            "## SQL Injection\n\n**Target:** $TARGET\n\n\`\`\`\n$(cat "$W/sqlmap/findings.txt" 2>/dev/null)\n\`\`\`" \
            "security,sqli,automated,critical"
    fi

    # ── Commix ──
    COMMIX_CNT=0
    if [ -f /opt/commix/commix.py ] && has_time 400; then
        head -3 "$W/params/urls_with_params.txt" > "$W/commix/targets.txt" 2>/dev/null || true
        if [ -s "$W/commix/targets.txt" ]; then
            while IFS= read -r url; do
                [ -z "$url" ] && continue
                [ "$(time_left)" -lt 200 ] && break
                timeout 60 python3 /opt/commix/commix.py -u "$url" \
                    --batch --random-agent --level=1 \
                    --output-dir="$W/commix/" 2>/dev/null | \
                    grep -iE 'vulnerable|injectable' >> "$W/commix/findings.txt" 2>/dev/null || true
            done < "$W/commix/targets.txt"
            COMMIX_CNT=$(grep -ci 'vulnerable' "$W/commix/findings.txt" 2>/dev/null || echo 0)
        fi
    fi
    ok "Commix RCE: $COMMIX_CNT"

    # ── Nikto ──
    NIKTO_CNT=0
    if HAS nikto && has_time 400; then
        head -2 "$W/recon/live.txt" > "$W/vulns/nikto_targets.txt" 2>/dev/null || true
        while IFS= read -r url; do
            [ -z "$url" ] && continue
            [ "$(time_left)" -lt 200 ] && break
            timeout 90 nikto -h "$url" -maxtime 60 -nointeractive -Tuning 123bde \
                -o "$W/vulns/nikto.txt" 2>/dev/null || true
        done < "$W/vulns/nikto_targets.txt"
        NIKTO_CNT=$(grep -cE '^\+ ' "$W/vulns/nikto.txt" 2>/dev/null || echo 0)
    fi
    ok "Nikto findings: $NIKTO_CNT"

    # ── Jaeles ──
    JAELES_CNT=0
    if HAS jaeles && has_time 600; then
        timeout 500 jaeles scan -s "cves" -s "common" \
            -U "$W/recon/live.txt" -o "$W/jaeles/findings.txt" 2>/dev/null || true
        JAELES_CNT=$(grep -c "Vulnerable" "$W/jaeles/findings.txt" 2>/dev/null || echo 0)
    fi
    ok "Jaeles findings: $JAELES_CNT"

    # ═══════════════════════════════════════════════════════
    #  PHASE 11 — Report Generation
    # ═══════════════════════════════════════════════════════
    hdr "PHASE 11/11 — Report Generation [$(time_left_h) left]"

    local T1; T1=$(date +%s); local DUR=$(( (T1-T0) / 60 ))

    {
        echo "# 🕰️ Legacy Hunter v4 Report — $TARGET"
        echo ""
        echo "**Date:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo "**Duration:** ${DUR}m"
        echo ""
        echo "---"
        echo ""
        echo "## 📊 Findings Summary"
        echo ""
        echo "| Scanner | Findings |"
        echo "|---------|----------|"
        echo "| Nuclei | $NUCLEI_CNT |"
        echo "| Dalfox XSS | $DALFOX_CNT |"
        echo "| SQLMap | $SQLMAP_CNT |"
        echo "| Commix | $COMMIX_CNT |"
        echo "| Nikto | $NIKTO_CNT |"
        echo "| Jaeles | $JAELES_CNT |"
        echo "| Unauthenticated 200 | $UNAUTH_CNT |"
        echo ""
        echo "---"
        echo ""
        echo "## 🎯 Recon Summary"
        echo ""
        echo "| Category | Count |"
        echo "|----------|-------|"
        echo "| Subdomains | $SUB_CNT |"
        echo "| Live Hosts | $LIVE_CNT |"
        echo "| Historical URLs | $HIST_CNT |"
        echo "| Live Historical URLs | $(cnt "$W/legacy/live_urls.txt") |"
        echo "| Sensitive/Backup Files | $(cnt "$W/backups/sensitive_files.txt") |"
        echo "| URLs with Params | $(cnt "$W/params/urls_with_params.txt") |"
        echo "| JS Endpoints | $(cnt "$W/js/js_endpoints.txt") |"
        echo "| JS Secrets | $(cnt "$W/js/js_secrets.txt") |"
        echo ""
        echo "---"
        echo ""
        echo "## 🎯 Manual Testing Guide"
        echo ""
        echo "### 1. Sensitive Files (اختبرها في المتصفح)"
        echo '```bash'
        echo "cat $W/backups/sensitive_files.txt | head -50"
        echo '```'
        echo ""
        echo "### 2. Unauthenticated Access (اكتشاف خطير!)"
        echo '```bash'
        echo "cat $W/vulns/unauth_access.txt"
        echo '```'
        echo ""
        echo "### 3. Nuclei Findings"
        echo '```bash'
        echo "cat $W/nuclei/merged.txt | head -100"
        echo '```'
        echo ""
        echo "### 4. JS Endpoints"
        echo '```bash'
        echo "cat $W/js/js_endpoints.txt | head -50"
        echo '```'
        echo ""
        echo "### 5. JS Secrets"
        echo '```bash'
        echo "cat $W/js/js_secrets.txt"
        echo '```'
        echo ""
        echo "### 6. WAF Detected"
        echo '```bash'
        echo "cat $W/waf/detected.txt"
        echo '```'
        echo ""
        echo "---"
        echo ""
        echo "**⚠️ Pure Recon — Verify manually.**"
    } > "$W/LEGACY_REPORT.md"

    # Save stats
    echo "$TARGET|$SUB_CNT|$LIVE_CNT|$HIST_CNT|$(cnt "$W/backups/sensitive_files.txt")|$(cnt "$W/params/urls_with_params.txt")|$NUCLEI_CNT|$DALFOX_CNT|$SQLMAP_CNT|$COMMIX_CNT|$NIKTO_CNT|$JAELES_CNT|$UNAUTH_CNT|$DUR" >> "$MASTER_STATS"

    notify "✅ *$TARGET* done — Nuclei:$NUCLEI_CNT Dalfox:$DALFOX_CNT SQLMap:$SQLMAP_CNT Unauth:$UNAUTH_CNT (batch time left: $(time_left_h))"
    ok "Report: $W/LEGACY_REPORT.md"
    echo -e "  ${CYAN}Duration:${NC} ${DUR}m | ${CYAN}Time left in batch:${NC} $(time_left_h)"
}

# ═══════════════════════════════════════════════════════════
#  MAIN LOOP
# ═══════════════════════════════════════════════════════════
for DOMAIN in "${DOMAINS[@]}"; do
    DOMAIN_CLEAN=$(echo "$DOMAIN" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')

    # تحقق لو فيه وقت قبل الدومين
    if ! has_time 300; then
        warn "No time left — skipping $DOMAIN_CLEAN"
        continue
    fi

    W="$ROOT/$DOMAIN_CLEAN"
    process_domain "$DOMAIN_CLEAN" "$W"
done

# ═══════════════════════════════════════════════════════════
#  MASTER REPORT
# ═══════════════════════════════════════════════════════════
{
    echo "# 🕰️ Legacy Hunter v4 — Master Report"
    echo ""
    echo "**Date:** $(date '+%Y-%m-%d %H:%M:%S')"
    echo "**Domains:** ${#DOMAINS[@]}"
    echo "**Total Time:** $(time_left_h) remaining / 4h 30m budget"
    echo ""
    echo "---"
    echo ""
    echo "## 📊 Summary Table"
    echo ""
    echo "| Domain | Subs | Live | URLs | Backups | Params | Nuclei | Dalfox | SQLMap | Commix | Nikto | Jaeles | Unauth | Time |"
    echo "|--------|------|------|------|---------|--------|--------|--------|--------|--------|-------|--------|--------|------|"
    while IFS='|' read -r d subs live hist backup params nuclei dalfox sqlmap commix nikto jaeles unauth time; do
        [ -z "$d" ] && continue
        echo "| **$d** | $subs | $live | $hist | $backup | $params | $nuclei | $dalfox | $sqlmap | $commix | $nikto | $jaeles | $unauth | ${time}m |"
    done < "$MASTER_STATS"
    echo ""
    echo "---"
    echo ""
    echo "## 🎯 Top Critical/High Findings"
    echo ""
    for DOMAIN in "${DOMAINS[@]}"; do
        d=$(echo "$DOMAIN" | sed 's#^https\?://##' | sed 's#/.*$##' | sed 's/:.*$//')
        [ -f "$ROOT/$d/nuclei/merged.txt" ] || continue
        critical=$(grep -iE '\[critical\]|\[high\]' "$ROOT/$d/nuclei/merged.txt" 2>/dev/null | head -10)
        [ -z "$critical" ] && continue
        echo "### $d"
        echo '```'
        echo "$critical"
        echo '```'
        echo ""
    done
} > "$ROOT/MASTER_LEGACY_REPORT.md"

TOTAL=$(awk -F'|' '{s+=$7+$8+$9+$10+$11+$12+$13} END {print s}' "$MASTER_STATS" 2>/dev/null || echo 0)

notify "🏁 *Legacy Hunter v4 finished* — ${#DOMAINS[@]} domains, $TOTAL total findings"

echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}${BOLD}║      ✅ LEGACY HUNTER v4 COMPLETED                       ║${NC}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${NC}"
echo -e "  Root:        $ROOT/"
echo -e "  Master:      $ROOT/MASTER_LEGACY_REPORT.md"
echo -e "  Time used:   $(( ( $(date +%s) - BATCH_START ) / 60 ))m"
echo -e "  Time left:   $(time_left_h)"
echo ""

# ⚠️ دايماً exit 0
exit 0
