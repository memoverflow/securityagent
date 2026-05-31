#!/usr/bin/env bash
# EC2：私有子网、无公网IP、user-data 自动部署靶站、systemd 托管
set -euo pipefail
# shellcheck source=scripts/00-config.sh
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 04 ec2"
PRIV_A=$(state_get PRIV_A)
SG_EC2=$(state_get SG_EC2)
IAM_PROFILE=$(state_get IAM_PROFILE)
APP_FILE="$(dirname "${BASH_SOURCE[0]}")/../app/server.js"
[ -n "$PRIV_A" ] && [ -n "$SG_EC2" ] && [ -f "$APP_FILE" ] || { echo "缺少前置资源/文件"; exit 1; }

# 最新 Amazon Linux 2023 AMI
AMI_ID=$(aws_cli ssm get-parameters \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' --output text)
state_set AMI_ID "$AMI_ID"

# Application secrets — generated at deploy time, injected via SSM Parameter Store
# so they are NOT embedded in user-data (accessible via IMDS / DescribeInstanceAttribute).
APP_SESSION_SECRET="${APP_SESSION_SECRET:-$(openssl rand -hex 32)}"
APP_SEED_PASSWORDS="${APP_SEED_PASSWORDS:-alice-pass-123,bob-pass-456,sup3r-s3cret}"
APP_SEED_SSNS="${APP_SEED_SSNS:-111-11-1111,222-22-2222,999-99-9999}"

# Store secrets in SSM Parameter Store (SecureString) — instance retrieves at boot
aws_cli ssm put-parameter --name "/${PROJECT}/session-secret" \
  --value "$APP_SESSION_SECRET" --type SecureString --overwrite
aws_cli ssm put-parameter --name "/${PROJECT}/seed-passwords" \
  --value "$APP_SEED_PASSWORDS" --type SecureString --overwrite
aws_cli ssm put-parameter --name "/${PROJECT}/seed-ssns" \
  --value "$APP_SEED_SSNS" --type SecureString --overwrite

# 将 server.js base64 嵌入 user-data (source no longer contains credentials)
APP_B64=$(base64 < "$APP_FILE" | tr -d '\n')

USER_DATA=$(cat <<EOF
#!/bin/bash
set -xe
dnf install -y nodejs npm gcc-c++ make
mkdir -p /opt/app
echo "${APP_B64}" | base64 -d > /opt/app/server.js
cd /opt/app
npm init -y
npm install express better-sqlite3

# Fetch secrets from SSM Parameter Store (not stored in user-data)
TOKEN=\$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
REGION=\$(curl -s -H "X-aws-ec2-metadata-token: \$TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
SESSION_SECRET=\$(aws ssm get-parameter --name "/${PROJECT}/session-secret" --with-decryption --region "\$REGION" --query 'Parameter.Value' --output text)
SEED_PASSWORDS=\$(aws ssm get-parameter --name "/${PROJECT}/seed-passwords" --with-decryption --region "\$REGION" --query 'Parameter.Value' --output text)
SEED_SSNS=\$(aws ssm get-parameter --name "/${PROJECT}/seed-ssns" --with-decryption --region "\$REGION" --query 'Parameter.Value' --output text)

cat > /opt/app/.env <<ENVFILE
PORT=${APP_PORT}
SESSION_SECRET=\$SESSION_SECRET
SEED_PASSWORDS=\$SEED_PASSWORDS
SEED_SSNS=\$SEED_SSNS
ENVFILE
chmod 600 /opt/app/.env

cat > /etc/systemd/system/pentest-app.service <<'UNIT'
[Unit]
Description=Pentest Target App
After=network.target
[Service]
EnvironmentFile=/opt/app/.env
WorkingDirectory=/opt/app
ExecStart=/usr/bin/node /opt/app/server.js
Restart=always
User=root
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now pentest-app
EOF
)
UD_B64=$(echo "$USER_DATA" | base64 | tr -d '\n')

INSTANCE_ID=$(aws_cli ec2 run-instances \
  --image-id "$AMI_ID" --instance-type "$INSTANCE_TYPE" \
  --subnet-id "$PRIV_A" --security-group-ids "$SG_EC2" \
  --iam-instance-profile "Name=${IAM_PROFILE}" \
  --no-associate-public-ip-address \
  --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled" \
  --user-data "$UD_B64" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Project,Value=${PROJECT}},{Key=Name,Value=${PROJECT}-app}]" \
  --query 'Instances[0].InstanceId' --output text)
state_set INSTANCE_ID "$INSTANCE_ID"

echo "  等待实例 running ..."
aws_cli ec2 wait instance-running --instance-ids "$INSTANCE_ID"
echo "  ✓ ec2 done (instance=${INSTANCE_ID}, 无公网IP, 应用经 user-data 部署中)"
