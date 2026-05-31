#!/usr/bin/env bash
# ALB：internet-facing ALB（入站由 SG-ALB 锁死）、target group、listener、注册 EC2
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 05 alb"
VPC_ID=$(state_get VPC_ID)
PUB_A=$(state_get PUB_A); PUB_B=$(state_get PUB_B)
SG_ALB=$(state_get SG_ALB)
INSTANCE_ID=$(state_get INSTANCE_ID)
[ -n "$VPC_ID" ] && [ -n "$SG_ALB" ] && [ -n "$INSTANCE_ID" ] || { echo "缺少前置资源"; exit 1; }

# ALB（scheme=internet-facing：可被 CloudFront 回源访问；真正的访问控制在 SG-ALB）
ALB_ARN=$(aws_cli elbv2 create-load-balancer --name "${PROJECT}-alb" \
  --subnets "$PUB_A" "$PUB_B" --security-groups "$SG_ALB" \
  --scheme internet-facing --type application \
  --tags "$TAG" \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text)
state_set ALB_ARN "$ALB_ARN"

ALB_DNS=$(aws_cli elbv2 describe-load-balancers --load-balancer-arns "$ALB_ARN" \
  --query 'LoadBalancers[0].DNSName' --output text)
state_set ALB_DNS "$ALB_DNS"

# Target group（指向 EC2 的 APP_PORT，健康检查 /health）
TG_ARN=$(aws_cli elbv2 create-target-group --name "${PROJECT}-tg" \
  --protocol HTTP --port "$APP_PORT" --vpc-id "$VPC_ID" \
  --target-type instance --health-check-path "/health" \
  --tags "$TAG" \
  --query 'TargetGroups[0].TargetGroupArn' --output text)
state_set TG_ARN "$TG_ARN"

aws_cli elbv2 register-targets --target-group-arn "$TG_ARN" \
  --targets "Id=${INSTANCE_ID},Port=${APP_PORT}" >/dev/null

# Listener: HTTP:80 -> TG（CloudFront 回源走 HTTP:80）
LISTENER_ARN=$(aws_cli elbv2 create-listener --load-balancer-arn "$ALB_ARN" \
  --protocol HTTP --port "$ALB_LISTEN_PORT" \
  --default-actions "Type=forward,TargetGroupArn=${TG_ARN}" \
  --query 'Listeners[0].ListenerArn' --output text)
state_set LISTENER_ARN "$LISTENER_ARN"

echo "  ✓ alb done (DNS=$ALB_DNS)"
echo "  注：等待目标健康可能需 2-4 分钟（含 user-data 安装时间）"
