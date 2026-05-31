#!/usr/bin/env bash
# IAM：EC2 用的 SSM 角色 + instance profile（用于 Session Manager 登录，不开 22 端口）
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 03 iam"
ROLE_NAME="${PROJECT}-ec2-ssm"
PROFILE_NAME="${PROJECT}-ec2-ssm"

TRUST='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'

# 角色（幂等：已存在则复用）
if ! aws_cli iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  aws_cli iam create-role --role-name "$ROLE_NAME" \
    --assume-role-policy-document "$TRUST" \
    --tags "$TAG" >/dev/null
fi
state_set IAM_ROLE "$ROLE_NAME"

aws_cli iam attach-role-policy --role-name "$ROLE_NAME" \
  --policy-arn "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore" >/dev/null

# instance profile
if ! aws_cli iam get-instance-profile --instance-profile-name "$PROFILE_NAME" >/dev/null 2>&1; then
  aws_cli iam create-instance-profile --instance-profile-name "$PROFILE_NAME" --tags "$TAG" >/dev/null
  aws_cli iam add-role-to-instance-profile --instance-profile-name "$PROFILE_NAME" --role-name "$ROLE_NAME" >/dev/null
fi
state_set IAM_PROFILE "$PROFILE_NAME"

echo "  等待 instance profile 生效 ..."
sleep 12
echo "  ✓ iam done (role=$ROLE_NAME)"
