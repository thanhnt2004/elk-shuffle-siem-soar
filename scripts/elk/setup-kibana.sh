#!/usr/bin/env bash
# Cấu hình Kibana: múi giờ, index mặc định của Security, data view, role + user analyst.
# Chạy lại nhiều lần vẫn an toàn.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/datn-env.sh"

echo "== Chờ Kibana sẵn sàng (tối đa 10 phút)"
for i in $(seq 1 120); do
  level=$(curl -s -m 5 -u "elastic:${ELASTIC_PASSWORD}" "${KIBANA_LOCAL_URL}/api/status" 2>/dev/null \
          | jq -r '.status.overall.level // empty' 2>/dev/null || true)
  if [ "$level" = "available" ]; then echo "Kibana: available"; break; fi
  [ "$i" = 120 ] && { echo "Kibana chưa sẵn sàng — xem: docker logs kibana" >&2; exit 1; }
  sleep 5
done

echo "== Múi giờ + định dạng ngày Việt Nam + index mặc định của Security"
kb POST /api/kibana/settings -d '{"changes":{
  "dateFormat:tz": "Asia/Ho_Chi_Minh",
  "dateFormat": "DD/MM/YYYY HH:mm:ss.SSS",
  "dateFormat:dow": "Monday",
  "securitySolution:defaultIndex": ["datn-*"]
}}' >/dev/null

echo "== Data view datn-*"
kb POST /api/data_views/data_view -d '{
  "override": true,
  "data_view": { "id": "datn-all", "title": "datn-*", "name": "DATN - tất cả log", "timeFieldName": "@timestamp" }
}' >/dev/null

echo "== Role datn_analyst"
kb PUT /api/security/role/datn_analyst -d '{
  "elasticsearch": {
    "cluster": [],
    "indices": [
      { "names": ["datn-*"], "privileges": ["read", "view_index_metadata"] },
      { "names": [".alerts-security.alerts-default", ".internal.alerts-security.alerts-default-*",
                  ".lists-default", ".items-default"],
        "privileges": ["read", "write", "view_index_metadata", "maintenance"] }
    ]
  },
  "kibana": [ { "base": ["all"], "spaces": ["default"] } ]
}' >/dev/null

echo "== User analyst"
es POST /_security/user/analyst \
  -d "{\"password\":\"${ANALYST_PASSWORD}\",\"roles\":[\"datn_analyst\"],\"full_name\":\"DATN analyst\"}" >/dev/null

echo "OK: setup-kibana xong. Kiểm tra tại ${KIBANA_LOCAL_URL}."
