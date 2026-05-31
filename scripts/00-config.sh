#!/usr/bin/env bash
# 公共配置变量 —— 被其他脚本 source
set -euo pipefail

export AWS_PROFILE="default"
export AWS_REGION="us-east-1"
export AWS_DEFAULT_REGION="us-east-1"

# 项目标识（所有资源打此 tag，便于审计/清理）
export PROJECT="securityagent-pentest-target"
export TAG="Key=Project,Value=${PROJECT}"

# 域名
export HOSTED_ZONE_ID="Z058329337MYAUUVDDY99"
export DOMAIN="pentest.oscine.io"

# 网络
export VPC_CIDR="10.20.0.0/16"
export PUBLIC_SUBNET_A_CIDR="10.20.1.0/24"
export PUBLIC_SUBNET_B_CIDR="10.20.2.0/24"
export PRIVATE_SUBNET_A_CIDR="10.20.11.0/24"

# 应用
export APP_PORT="3000"
export INSTANCE_TYPE="t3.micro"

# CloudFront 回源用 HTTP:80（ALB 入站由托管前缀列表锁死，无 0.0.0.0/0）
export ALB_LISTEN_PORT="80"

# CloudFront 自定义源头验证（应用层防绕过）
export CF_ORIGIN_VERIFY_HEADER="X-Origin-Verify"
export CF_ORIGIN_VERIFY_SECRET="${CF_ORIGIN_VERIFY_SECRET:-$(openssl rand -hex 32)}"

# 状态文件（记录已创建资源 ID，供 destroy 使用）
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export STATE_FILE="${SCRIPT_DIR}/.state"

# ---- 状态读写辅助 ----
state_set() { # state_set KEY VALUE
  local key="$1" val="$2"
  touch "$STATE_FILE"
  grep -v "^${key}=" "$STATE_FILE" > "${STATE_FILE}.tmp" 2>/dev/null || true
  mv "${STATE_FILE}.tmp" "$STATE_FILE"
  echo "${key}=${val}" >> "$STATE_FILE"
  echo "  [state] ${key}=${val}"
}

state_get() { # state_get KEY
  [ -f "$STATE_FILE" ] || return 0
  grep "^${1}=" "$STATE_FILE" | tail -1 | cut -d= -f2-
}

aws_cli() { aws --profile "$AWS_PROFILE" --region "$AWS_REGION" "$@"; }
