#!/usr/bin/env bash
# CloudFront：客户端 HTTPS（ACM证书）、回源 HTTP:80 到 ALB、绑定 pentest.oscine.io
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 07 cloudfront"
ALB_DNS=$(state_get ALB_DNS)
CERT_ARN=$(state_get CERT_ARN)
[ -n "$ALB_DNS" ] && [ -n "$CERT_ARN" ] || { echo "缺少 ALB_DNS / CERT_ARN"; exit 1; }

CALLER_REF="${PROJECT}-$(date +%s)"

# 使用 AWS 托管缓存策略 CachingDisabled（靶站动态内容，禁缓存便于测试）
CACHE_POLICY_ID="4135ea2d-6df8-44a3-9df3-4b5a84be39ad" # Managed-CachingDisabled
# 转发所有 viewer 请求头/查询串/cookie 的 origin request policy: AllViewer
ORIGIN_REQ_POLICY_ID="216adef6-5c7f-47e4-b989-5492eafa07d3" # Managed-AllViewer

CONFIG=$(cat <<EOF
{
  "CallerReference": "${CALLER_REF}",
  "Aliases": {"Quantity": 1, "Items": ["${DOMAIN}"]},
  "DefaultRootObject": "",
  "Origins": {"Quantity": 1, "Items": [{
    "Id": "alb-origin",
    "DomainName": "${ALB_DNS}",
    "CustomOriginConfig": {
      "HTTPPort": ${ALB_LISTEN_PORT},
      "HTTPSPort": 443,
      "OriginProtocolPolicy": "http-only",
      "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]}
    }
  }]},
  "DefaultCacheBehavior": {
    "TargetOriginId": "alb-origin",
    "ViewerProtocolPolicy": "redirect-to-https",
    "CachePolicyId": "${CACHE_POLICY_ID}",
    "OriginRequestPolicyId": "${ORIGIN_REQ_POLICY_ID}",
    "AllowedMethods": {"Quantity": 7,
      "Items": ["GET","HEAD","OPTIONS","PUT","POST","PATCH","DELETE"],
      "CachedMethods": {"Quantity": 2, "Items": ["GET","HEAD"]}}
  },
  "Comment": "${PROJECT}",
  "Enabled": true,
  "ViewerCertificate": {
    "ACMCertificateArn": "${CERT_ARN}",
    "SSLSupportMethod": "sni-only",
    "MinimumProtocolVersion": "TLSv1.2_2021"
  }
}
EOF
)

OUT=$(aws_cli cloudfront create-distribution --distribution-config "$CONFIG")
CF_ID=$(echo "$OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["Distribution"]["Id"])')
CF_DOMAIN=$(echo "$OUT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["Distribution"]["DomainName"])')
state_set CF_ID "$CF_ID"
state_set CF_DOMAIN "$CF_DOMAIN"

# CloudFront alias 记录需要的固定 HostedZoneId
state_set CF_HOSTED_ZONE "Z2FDTNDATAQYW2"

echo "  分配创建: $CF_ID ($CF_DOMAIN)"
echo "  等待 CloudFront 部署完成（约 5-15 分钟）..."
aws_cli cloudfront wait distribution-deployed --id "$CF_ID"
echo "  ✓ cloudfront done"
