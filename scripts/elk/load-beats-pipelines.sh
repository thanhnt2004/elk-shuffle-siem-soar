#!/usr/bin/env bash
# Nạp ingest pipeline của Filebeat module system + auditd (đúng STACK_VERSION).
# Pipeline Winlogbeat nạp từ máy quản trị qua SSH tunnel.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/datn-env.sh"

docker run --rm --network elk \
  -v "$DATN_ELK_DIR/certs/ca/ca.crt:/tmp/ca.crt:ro" \
  "docker.elastic.co/beats/filebeat:${STACK_VERSION}" \
  setup --pipelines --modules system,auditd --force-enable-module-filesets \
  -E output.logstash.enabled=false \
  -E 'output.elasticsearch.hosts=["https://elasticsearch:9200"]' \
  -E output.elasticsearch.username=elastic \
  -E "output.elasticsearch.password=${ELASTIC_PASSWORD}" \
  -E 'output.elasticsearch.ssl.certificate_authorities=["/tmp/ca.crt"]'

echo "== Pipeline Filebeat hiện có:"
es GET '/_ingest/pipeline/filebeat-*' | jq -r 'keys[]'
