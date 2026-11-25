# Source this file from Bash to load the export's ELK settings.
DATN_ELK_DIR="${DATN_ELK_DIR:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../../configs/elk" && pwd)}"
KIBANA_LOCAL_URL="${KIBANA_LOCAL_URL:-http://127.0.0.1:5601}"
if [ ! -f "$DATN_ELK_DIR/.env" ]; then
  echo "Thiếu $DATN_ELK_DIR/.env. Tạo file từ .env.example trước." >&2
  return 1 2>/dev/null || exit 1
fi
set -a
. "$DATN_ELK_DIR/.env"
set +a

es() {
  local m=$1 p=$2; shift 2
  curl -sS --fail-with-body --cacert "$DATN_ELK_DIR/certs/ca/ca.crt" -u "elastic:${ELASTIC_PASSWORD}" \
    -H 'Content-Type: application/json' -X "$m" "https://localhost:9200${p}" "$@"
  local rc=$?; echo; return $rc
}

kb() {
  local m=$1 p=$2; shift 2
  # x-elastic-internal-origin: Kibana 9 chặn API nội bộ (vd /api/kibana/settings) nếu thiếu header này (lỗi 400)
  curl -sS --fail-with-body -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: true' \
    -H 'x-elastic-internal-origin: kibana' \
    -H 'Content-Type: application/json' -X "$m" "${KIBANA_LOCAL_URL}${p}" "$@"
  local rc=$?; echo; return $rc
}
