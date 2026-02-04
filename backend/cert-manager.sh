#!/bin/bash
# --- Configuration ---
# BASE_DIR is where the script lives
BASE_DIR=$(dirname $(readlink -f "$0"))
API_BASE_URL="https://splrootca/api"
POLL_INTERVAL=30
RENEW_WINDOW_DAYS=14
SCRIPT_PATH=$(readlink -f "$0")

if [ "$EUID" -ne 0 ]; then echo "Please run as root"; exit 1; fi

# --- OpenSSL Config Handler ---
prepare_openssl_cfg() {
    local APP=$1
    local APP_DIR=$2
    local CFG_FILE="$APP_DIR/$APP.cfg"

    # Default values
    local D_C="US"
    local D_ST="California"
    local D_L="Clovis"
    local D_O="SPL"
    local D_OU="IT"
    local D_CN="$APP.pathologyassociates.local"

    echo "--- Initial Setup: Identity for $APP ---"
    read -p "Country [$D_C]: " C; C=${C:-$D_C}
    read -p "State [$D_ST]: " ST; ST=${ST:-$D_ST}
    read -p "City [$D_L]: " L; L=${L:-$D_L}
    read -p "Organization [$D_O]: " O; O=${O:-$D_O}
    read -p "OU [$D_OU]: " OU; OU=${OU:-$D_OU}
    read -p "Common Name (Primary DNS) [$D_CN]: " CN; CN=${CN:-$D_CN}

    local SAN_LIST="DNS:$CN"
    echo "--- Additional Subject Alternative Names (SAN) ---"
    while true; do
        read -p "Add DNS Name (or Enter to skip): " ALT_DNS
        [ -z "$ALT_DNS" ] && break
        SAN_LIST+=",DNS:$ALT_DNS"
    done
    while true; do
        read -p "Add IP Address (or Enter to skip): " ALT_IP
        [ -z "$ALT_IP" ] && break
        SAN_LIST+=",IP:$ALT_IP"
    done

    cat <<EOF > "$CFG_FILE"
[ req ]
default_bits       = 2048
distinguished_name = req_distinguished_name
req_extensions     = v3_req
prompt             = no

[ req_distinguished_name ]
C  = $C
ST = $ST
L  = $L
O  = $O
OU = $OU
CN = $CN

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = $SAN_LIST
EOF
}

# --- Crontab Automation ---
ensure_cron_entry() {
    local APP=$1
    local APP_DIR=$2
    local CRON_CMD="0 6 * * * $SCRIPT_PATH $APP >> $APP_DIR/renewal.log 2>&1"
    if ! crontab -l 2>/dev/null | grep -q "$SCRIPT_PATH $APP"; then
        (crontab -l 2>/dev/null; echo "$CRON_CMD") | crontab -
        echo "✔ Crontab entry added (6 AM daily)."
    fi
}

# --- Main Logic ---
manage_cert() {
    local APP=$1
    local APP_DIR="$BASE_DIR/$APP"

    # Create the subdirectory if it doesn't exist
    mkdir -p "$APP_DIR"

    local PENDING_FILE="$APP_DIR/pending.id"
    local KEY_FILE="$APP_DIR/server.key"
    local CRT_FILE="$APP_DIR/server.crt"
    local CFG_FILE="$APP_DIR/$APP.cfg"

    ensure_cron_entry "$APP" "$APP_DIR"

    # 1. RESUME PENDING
    if [ -f "$PENDING_FILE" ]; then
        local REQ_ID=$(cat "$PENDING_FILE")
        echo "Resuming pending request ID: $REQ_ID..."
        poll_status "$APP" "$REQ_ID" "$APP_DIR"
        return
    fi

    # 2. CHECK EXPIRY
    if [ -f "$CRT_FILE" ]; then
        if openssl x509 -checkend $(( $RENEW_WINDOW_DAYS * 86400 )) -in "$CRT_FILE" > /dev/null; then
            echo "✔ Cert for $APP is healthy."
            return
        fi
        echo "Certificate for $APP is expiring soon."
    fi

    # 3. CONFIGURE & SUBMIT
    [ ! -f "$CFG_FILE" ] && prepare_openssl_cfg "$APP" "$APP_DIR"

    if [ ! -f "$KEY_FILE" ]; then
        openssl genrsa -out "$KEY_FILE" 2048
        chmod 600 "$KEY_FILE"
    fi

    local CSR_B64=$(openssl req -new -key "$KEY_FILE" -config "$CFG_FILE" -extensions v3_req | base64 -w 0)

    echo "Contacting $API_BASE_URL/renew..."
    local RESP=$(curl -k -s -X POST "$API_BASE_URL/renew" -H "Content-Type: application/json" -d "{\"req\": \"$CSR_B64\"}")

    if [[ "$RESP" == *"BEGIN CERTIFICATE"* ]]; then
        echo "$RESP" > "$CRT_FILE"
        echo "✔ Auto-renewal successful."
        command -v nginx >/dev/null 2>&1 && nginx -t && systemctl reload nginx
        return
    fi

    echo "Submitting manual request..."
    RESP=$(curl -k -s -X POST "$API_BASE_URL/request" -H "Content-Type: application/json" -d "{\"req\": \"$CSR_B64\"}")
    local REQ_ID=$(echo "$RESP" | grep -oP '(?<="uuid":")[0-9a-f-]+')

    if [ -z "$REQ_ID" ]; then
        echo "✘ Error: API Response: $RESP"
        exit 1
    fi

    echo "$REQ_ID" > "$PENDING_FILE"
    poll_status "$APP" "$REQ_ID" "$APP_DIR"
}

poll_status() {
    local APP=$1
    local REQ_ID=$2
    local APP_DIR=$3
    local CRT_FILE="$APP_DIR/server.crt"
    local PENDING_FILE="$APP_DIR/pending.id"

    echo "Polling for approval (ID $REQ_ID)..."
    while true; do
        local RESP=$(curl -k -s "$API_BASE_URL/request/$REQ_ID")
        local STATUS=$(echo "$RESP" | grep -oP '(?<="status":")[^"]+')

        case "$STATUS" in
            "issued")
                echo -e "\n✔ Issued!"
                echo "$RESP" | grep -oP '(?<="b64Cert":")[^"]+' | base64 -d > "$CRT_FILE"
                chmod 600 "$CRT_FILE"
                rm "$PENDING_FILE"
                command -v nginx >/dev/null 2>&1 && nginx -t && systemctl reload nginx
                exit 0 ;;
            "denied")
                echo -e "\n✘ Denied by Admin."
                rm "$PENDING_FILE"
                exit 1 ;;
            "failed")
                echo -e "\n✘ Request failed."
                rm "$PENDING_FILE"
                exit 1 ;;
            "pending_submit"|"submitted")
                echo -n "."
                sleep "$POLL_INTERVAL" ;;
            *) sleep "$POLL_INTERVAL" ;;
        esac
    done
}

# --- Execution ---
APP_NAME=${1:-$(read -p "App Name: " val && echo $val)}
manage_cert "$APP_NAME"