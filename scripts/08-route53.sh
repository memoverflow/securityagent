#!/usr/bin/env bash
# Route53：pentest.oscine.io  A记录 Alias → CloudFront
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 08 route53"
CF_DOMAIN=$(state_get CF_DOMAIN)
CF_HOSTED_ZONE=$(state_get CF_HOSTED_ZONE)
[ -n "$CF_DOMAIN" ] || { echo "缺少 CF_DOMAIN"; exit 1; }

CHANGE=$(cat <<EOF
{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{
  "Name":"${DOMAIN}","Type":"A",
  "AliasTarget":{"HostedZoneId":"${CF_HOSTED_ZONE}","DNSName":"${CF_DOMAIN}","EvaluateTargetHealth":false}
}}]}
EOF
)
aws_cli route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" \
  --change-batch "$CHANGE" --query 'ChangeInfo.Id' --output text >/dev/null
state_set DNS_A_RECORD "$DOMAIN"
echo "  ✓ route53 done ($DOMAIN -> $CF_DOMAIN)"
