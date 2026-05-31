#!/usr/bin/env bash
# 顺序编排部署
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

bash 01-network.sh
bash 02-security-groups.sh
bash 03-iam.sh
bash 04-ec2.sh
bash 05-alb.sh
bash 06-acm.sh
bash 07-cloudfront.sh
bash 08-route53.sh

echo ""
echo "======================================================"
echo " 部署完成。访问: https://pentest.oscine.io/"
echo " （DNS 传播 + CloudFront 生效后可访问）"
echo "======================================================"
