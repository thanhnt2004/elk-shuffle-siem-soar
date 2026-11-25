#!/usr/bin/env bash
# Khởi tạo Elasticsearch: mật khẩu kibana_system, role/user Logstash, ILM,
# index template, index báo cáo. Chạy lại nhiều lần vẫn an toàn.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/datn-env.sh"

echo "== Kết nối Elasticsearch"
es GET / | jq -r '"version " + .version.number'
es GET /_license | jq -r '"license " + .license.type'

echo "== Mật khẩu kibana_system"
es POST /_security/user/kibana_system/_password -d "{\"password\":\"${KIBANA_PASSWORD}\"}" >/dev/null

echo "== Role + user logstash_writer"
es PUT /_security/role/datn_logstash_writer -d '{
  "cluster": ["monitor"],
  "indices": [ { "names": ["datn-*"], "privileges": ["create_doc", "create_index", "auto_configure"] } ]
}' >/dev/null
es POST /_security/user/logstash_writer \
  -d "{\"password\":\"${LOGSTASH_WRITER_PASSWORD}\",\"roles\":[\"datn_logstash_writer\"],\"full_name\":\"Logstash DATN\"}" >/dev/null

echo "== ILM datn-30d"
es PUT /_ilm/policy/datn-30d -d '{
  "policy": { "phases": {
    "hot":    { "actions": {} },
    "delete": { "min_age": "30d", "actions": { "delete": {} } }
  } }
}' >/dev/null

if es GET /_component_template/ecs@mappings >/dev/null 2>&1; then
  COMPOSED='"composed_of": ["ecs@mappings"],'
  echo "== Có ecs@mappings, dùng làm nền cho template"
else
  COMPOSED=''
  echo "== Không có ecs@mappings, template chỉ dùng mapping khai báo"
fi

echo "== Index template datn-default"
es PUT /_index_template/datn-default --data-binary @- >/dev/null <<EOF
{
  "index_patterns": ["datn-*"],
  "priority": 200,
  ${COMPOSED}
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "datn-30d",
      "index.refresh_interval": "5s",
      "index.mapping.total_fields.limit": 3000
    },
    "mappings": {
      "properties": {
        "@timestamp":  { "type": "date" },
        "event":       { "properties": { "ingested": { "type": "date" } } },
        "source":      { "properties": { "ip": { "type": "ip" }, "port": { "type": "long" } } },
        "destination": { "properties": { "ip": { "type": "ip" }, "port": { "type": "long" } } },
        "http":        { "properties": { "response": { "properties": { "status_code": { "type": "long" } } } } },
        "url":         { "properties": { "original": { "type": "keyword", "ignore_above": 4096,
                                                       "fields": { "text": { "type": "match_only_text" } } } } },
        "labels":      { "properties": { "cookie_present": { "type": "boolean" } } },
        "message":     { "type": "match_only_text" }
      }
    }
  }
}
EOF

echo "== Index template datn-reports (không ILM)"
es PUT /_index_template/datn-reports --data-binary @- >/dev/null <<'EOF'
{
  "index_patterns": ["datn-tests*", "datn-soar-results*"],
  "priority": 300,
  "template": {
    "settings": { "number_of_shards": 1, "number_of_replicas": 0 },
    "mappings": {
      "dynamic_templates": [
        { "strings": { "match_mapping_type": "string", "mapping": { "type": "keyword", "ignore_above": 1024 } } }
      ],
      "properties": {
        "@timestamp": { "type": "date" },
        "test_id": { "type": "keyword" }, "playbook_id": { "type": "keyword" }, "rule_id": { "type": "keyword" },
        "alert_id": { "type": "keyword" }, "execution_id": { "type": "keyword" },
        "t0": { "type": "date" }, "t1": { "type": "date" }, "t2": { "type": "date" }, "t3": { "type": "date" },
        "t4": { "type": "date" }, "t5": { "type": "date" }, "t6": { "type": "date" },
        "verified": { "type": "boolean" },
        "notes": { "type": "text" }
      }
    }
  }
}
EOF

for idx in datn-tests datn-soar-results; do
  if es GET "/${idx}" >/dev/null 2>&1; then
    echo "== Index ${idx} đã có"
  else
    es PUT "/${idx}" >/dev/null
    echo "== Đã tạo index ${idx}"
  fi
done

echo "== Kiểm tra"
es GET '/_cat/indices/datn-*?v&h=health,status,index,docs.count'
echo "OK: setup-es xong"
