#!/usr/bin/env bash
# ACM：在 us-east-1 为 pentest.oscine.io 申请证书，DNS 验证（自动写 Route53 CNAME）
# 注意：此 CNAME 是 ACM 证书验证用，与 Security Agent 域名验证的 TXT 无关
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 06 acm"

CERT_ARN=$(aws_cli acm request-certificate --domain-name "$DOMAIN" \
  --validation-method DNS \
  --tags "$TAG" \
  --query 'CertificateArn' --output text)
state_set CERT_ARN "$CERT_ARN"
echo "  证书申请: $CERT_ARN"

# 等待验证记录生成
echo "  等待 ACM 生成 DNS 验证记录 ..."
for i in $(seq 1 30); do
  RR_NAME=$(aws_cli acm describe-certificate --certificate-arn "$CERT_ARN" \
    --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Name' --output text 2>/dev/null || true)
  [ -n "$RR_NAME" ] && [ "$RR_NAME" != "None" ] && break
  sleep 5
done
RR_VALUE=$(aws_cli acm describe-certificate --certificate-arn "$CERT_ARN" \
  --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Value' --output text)
[ -n "$RR_NAME" ] && [ "$RR_NAME" != "None" ] || { echo "未获取到验证记录"; exit 1; }

# 写入 Route53 验证 CNAME
CHANGE=$(cat <<EOF
{"Changes":[{"Action":"UPSERT","ResourceRecordSet":{
  "Name":"${RR_NAME}","Type":"CNAME","TTL":300,
  "ResourceRecords":[{"Value":"${RR_VALUE}"}]}}]}
EOF
)
CHANGE_ID=$(aws_cli route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" \
  --change-batch "$CHANGE" --query 'ChangeInfo.Id' --output text)
state_set ACM_VALIDATION_NAME "$RR_NAME"
echo "  已写入验证 CNAME，等待证书 ISSUED（可能需几分钟）..."

aws_cli acm wait certificate-validated --certificate-arn "$CERT_ARN"
echo "  ✓ acm done (证书已签发)"
