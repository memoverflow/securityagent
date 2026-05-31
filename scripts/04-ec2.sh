#!/usr/bin/env bash
# EC2：私有子网、无公网IP、user-data 自动部署靶站、systemd 托管
set -euo pipefail
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

# 将 server.js base64 嵌入 user-data，避免引号转义问题
APP_B64=$(base64 < "$APP_FILE" | tr -d '\n')

USER_DATA=$(cat <<EOF
#!/bin/bash
set -xe
useradd -r -s /sbin/nologin nodeapp || true
dnf install -y nodejs npm gcc-c++ make
mkdir -p /opt/app
echo "${APP_B64}" | base64 -d > /opt/app/server.js
cd /opt/app
npm init -y
npm install express better-sqlite3
chown -R nodeapp:nodeapp /opt/app
cat > /etc/systemd/system/pentest-app.service <<'UNIT'
[Unit]
Description=Pentest Target App
After=network.target
[Service]
Environment=PORT=${APP_PORT}
WorkingDirectory=/opt/app
ExecStart=/usr/bin/node /opt/app/server.js
Restart=always
User=nodeapp
Group=nodeapp
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/opt/app
CapabilityBoundingSet=
RestrictSUIDSGID=true
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
  --metadata-options "HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=1" \
  --user-data "$UD_B64" \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Project,Value=${PROJECT}},{Key=Name,Value=${PROJECT}-app}]" \
  --query 'Instances[0].InstanceId' --output text)
state_set INSTANCE_ID "$INSTANCE_ID"

echo "  等待实例 running ..."
aws_cli ec2 wait instance-running --instance-ids "$INSTANCE_ID"
echo "  ✓ ec2 done (instance=${INSTANCE_ID}, 无公网IP, 应用经 user-data 部署中)"
