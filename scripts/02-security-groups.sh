#!/usr/bin/env bash
# 安全组 ★约束核心★
#   SG-ALB inbound: 仅 CloudFront 托管前缀列表（无 0.0.0.0/0）
#   SG-EC2 inbound: 仅 source = SG-ALB（无 0.0.0.0/0）
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 02 security-groups"
VPC_ID=$(state_get VPC_ID)
[ -n "$VPC_ID" ] || { echo "缺少 VPC_ID"; exit 1; }

TAGSPEC() { echo "ResourceType=security-group,Tags=[{Key=Project,Value=${PROJECT}},{Key=Name,Value=${PROJECT}-$1}]"; }

# CloudFront 回源托管前缀列表 ID
CF_PL_ID=$(aws_cli ec2 describe-managed-prefix-lists \
  --filters "Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing" \
  --query 'PrefixLists[0].PrefixListId' --output text)
[ -n "$CF_PL_ID" ] && [ "$CF_PL_ID" != "None" ] || { echo "未找到 CloudFront 托管前缀列表"; exit 1; }
state_set CF_PL_ID "$CF_PL_ID"
echo "  CloudFront prefix list = $CF_PL_ID"

# SG-ALB
SG_ALB=$(aws_cli ec2 create-security-group --group-name "${PROJECT}-alb" \
  --description "ALB SG - inbound only from CloudFront managed prefix list" \
  --vpc-id "$VPC_ID" --tag-specifications "$(TAGSPEC alb)" \
  --query 'GroupId' --output text); state_set SG_ALB "$SG_ALB"

# SG-ALB inbound: 80 <- CloudFront 前缀列表（★绝无 0.0.0.0/0）
aws_cli ec2 authorize-security-group-ingress --group-id "$SG_ALB" \
  --ip-permissions "IpProtocol=tcp,FromPort=${ALB_LISTEN_PORT},ToPort=${ALB_LISTEN_PORT},PrefixListIds=[{PrefixListId=${CF_PL_ID},Description=cloudfront-origin-facing}]" >/dev/null

# SG-EC2
SG_EC2=$(aws_cli ec2 create-security-group --group-name "${PROJECT}-ec2" \
  --description "EC2 SG - inbound only from ALB SG" \
  --vpc-id "$VPC_ID" --tag-specifications "$(TAGSPEC ec2)" \
  --query 'GroupId' --output text); state_set SG_EC2 "$SG_EC2"

# SG-EC2 inbound: APP_PORT <- source SG-ALB（★绝无 0.0.0.0/0）
aws_cli ec2 authorize-security-group-ingress --group-id "$SG_EC2" \
  --ip-permissions "IpProtocol=tcp,FromPort=${APP_PORT},ToPort=${APP_PORT},UserIdGroupPairs=[{GroupId=${SG_ALB},Description=from-alb}]" >/dev/null

# ---- 校验：确认两个 SG 的 inbound 都不含 0.0.0.0/0 ----
echo "  校验 inbound 无 0.0.0.0/0 ..."
for sg in "$SG_ALB" "$SG_EC2"; do
  CIDRS=$(aws_cli ec2 describe-security-groups --group-ids "$sg" \
    --query 'SecurityGroups[0].IpPermissions[].IpRanges[].CidrIp' --output text)
  if echo "$CIDRS" | grep -q "0.0.0.0/0"; then
    echo "  ✗ 安全违规：$sg inbound 含 0.0.0.0/0"; exit 1
  fi
done
echo "  ✓ security-groups done (ALB=$SG_ALB EC2=$SG_EC2，无 0.0.0.0/0)"
