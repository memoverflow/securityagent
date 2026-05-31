#!/usr/bin/env bash
# 逆序清理所有资源（依据 .state 记录的 ID，仅删本项目资源）
set -uo pipefail   # 不用 -e：清理需尽量继续
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> destroy（逆序清理）"
g() { state_get "$1"; }

# 08 Route53 A 记录
CF_DOMAIN=$(g CF_DOMAIN); CF_HZ=$(g CF_HOSTED_ZONE)
if [ -n "$(g DNS_A_RECORD)" ] && [ -n "$CF_DOMAIN" ]; then
  aws_cli route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch \
    "{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":{\"Name\":\"${DOMAIN}\",\"Type\":\"A\",\"AliasTarget\":{\"HostedZoneId\":\"${CF_HZ}\",\"DNSName\":\"${CF_DOMAIN}\",\"EvaluateTargetHealth\":false}}}]}" >/dev/null 2>&1 && echo "  删除 A 记录" || true
fi

# 07 CloudFront：先 disable 再删
CF_ID=$(g CF_ID)
if [ -n "$CF_ID" ]; then
  echo "  禁用 CloudFront $CF_ID ..."
  ETAG=$(aws_cli cloudfront get-distribution-config --id "$CF_ID" --query 'ETag' --output text 2>/dev/null || true)
  if [ -n "$ETAG" ]; then
    aws_cli cloudfront get-distribution-config --id "$CF_ID" --query 'DistributionConfig' > /tmp/cf-cfg.json 2>/dev/null
    python3 -c 'import json;d=json.load(open("/tmp/cf-cfg.json"));d["Enabled"]=False;json.dump(d,open("/tmp/cf-cfg.json","w"))'
    aws_cli cloudfront update-distribution --id "$CF_ID" --distribution-config file:///tmp/cf-cfg.json --if-match "$ETAG" >/dev/null 2>&1 || true
    echo "  等待禁用部署完成 ..."
    aws_cli cloudfront wait distribution-deployed --id "$CF_ID" 2>/dev/null || true
    ETAG2=$(aws_cli cloudfront get-distribution-config --id "$CF_ID" --query 'ETag' --output text 2>/dev/null || true)
    aws_cli cloudfront delete-distribution --id "$CF_ID" --if-match "$ETAG2" 2>/dev/null && echo "  删除 CloudFront" || echo "  CloudFront 删除失败（可能仍在禁用中，稍后重试）"
  fi
fi

# 06 ACM 验证 CNAME + 证书
VN=$(g ACM_VALIDATION_NAME); CERT_ARN=$(g CERT_ARN)
if [ -n "$VN" ]; then
  VV=$(aws_cli acm describe-certificate --certificate-arn "$CERT_ARN" --query 'Certificate.DomainValidationOptions[0].ResourceRecord.Value' --output text 2>/dev/null || true)
  [ -n "$VV" ] && [ "$VV" != "None" ] && aws_cli route53 change-resource-record-sets --hosted-zone-id "$HOSTED_ZONE_ID" --change-batch \
    "{\"Changes\":[{\"Action\":\"DELETE\",\"ResourceRecordSet\":{\"Name\":\"${VN}\",\"Type\":\"CNAME\",\"TTL\":300,\"ResourceRecords\":[{\"Value\":\"${VV}\"}]}}]}" >/dev/null 2>&1 && echo "  删除 ACM 验证 CNAME" || true
fi
[ -n "$CERT_ARN" ] && aws_cli acm delete-certificate --certificate-arn "$CERT_ARN" 2>/dev/null && echo "  删除证书" || true

# 05 ALB / TG
ALB_ARN=$(g ALB_ARN); TG_ARN=$(g TG_ARN)
[ -n "$ALB_ARN" ] && aws_cli elbv2 delete-load-balancer --load-balancer-arn "$ALB_ARN" 2>/dev/null && echo "  删除 ALB" || true
sleep 20
[ -n "$TG_ARN" ] && aws_cli elbv2 delete-target-group --target-group-arn "$TG_ARN" 2>/dev/null && echo "  删除 TG" || true

# 04 EC2
INSTANCE_ID=$(g INSTANCE_ID)
if [ -n "$INSTANCE_ID" ]; then
  aws_cli ec2 terminate-instances --instance-ids "$INSTANCE_ID" >/dev/null 2>&1 && echo "  终止 EC2 ..."
  aws_cli ec2 wait instance-terminated --instance-ids "$INSTANCE_ID" 2>/dev/null || true
fi

# 03 IAM
PROFILE=$(g IAM_PROFILE); ROLE=$(g IAM_ROLE)
if [ -n "$PROFILE" ]; then
  aws_cli iam remove-role-from-instance-profile --instance-profile-name "$PROFILE" --role-name "$ROLE" 2>/dev/null || true
  aws_cli iam delete-instance-profile --instance-profile-name "$PROFILE" 2>/dev/null && echo "  删除 instance profile" || true
fi
if [ -n "$ROLE" ]; then
  aws_cli iam detach-role-policy --role-name "$ROLE" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null || true
  aws_cli iam delete-role-policy --role-name "$ROLE" --policy-name "${PROJECT}-ssm-params-read" 2>/dev/null || true
  aws_cli iam delete-role --role-name "$ROLE" 2>/dev/null && echo "  删除 IAM 角色" || true
fi

# SSM Parameter Store secrets cleanup
aws_cli ssm delete-parameter --name "/${PROJECT}/session-secret" 2>/dev/null || true
aws_cli ssm delete-parameter --name "/${PROJECT}/seed-passwords" 2>/dev/null || true
aws_cli ssm delete-parameter --name "/${PROJECT}/seed-ssns" 2>/dev/null || true
echo "  删除 SSM 参数"

# 02 安全组（先删 EC2 SG 再删 ALB SG，因有引用关系）
SG_EC2=$(g SG_EC2); SG_ALB=$(g SG_ALB)
[ -n "$SG_EC2" ] && aws_cli ec2 delete-security-group --group-id "$SG_EC2" 2>/dev/null && echo "  删除 SG-EC2" || true
[ -n "$SG_ALB" ] && aws_cli ec2 delete-security-group --group-id "$SG_ALB" 2>/dev/null && echo "  删除 SG-ALB" || true

# 01 网络
NAT_ID=$(g NAT_ID)
if [ -n "$NAT_ID" ]; then
  aws_cli ec2 delete-nat-gateway --nat-gateway-id "$NAT_ID" >/dev/null 2>&1 && echo "  删除 NAT ..."
  aws_cli ec2 wait nat-gateway-deleted --nat-gateway-ids "$NAT_ID" 2>/dev/null || true
fi
EIP_ALLOC=$(g EIP_ALLOC)
[ -n "$EIP_ALLOC" ] && aws_cli ec2 release-address --allocation-id "$EIP_ALLOC" 2>/dev/null && echo "  释放 EIP" || true

RT_PUB=$(g RT_PUB); RT_PRIV=$(g RT_PRIV)
for rt in "$RT_PUB" "$RT_PRIV"; do
  [ -n "$rt" ] || continue
  for assoc in $(aws_cli ec2 describe-route-tables --route-table-ids "$rt" --query 'RouteTables[0].Associations[?!Main].RouteTableAssociationId' --output text 2>/dev/null); do
    aws_cli ec2 disassociate-route-table --association-id "$assoc" 2>/dev/null || true
  done
  aws_cli ec2 delete-route-table --route-table-id "$rt" 2>/dev/null && echo "  删除路由表 $rt" || true
done

IGW_ID=$(g IGW_ID); VPC_ID=$(g VPC_ID)
if [ -n "$IGW_ID" ]; then
  aws_cli ec2 detach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID" 2>/dev/null || true
  aws_cli ec2 delete-internet-gateway --internet-gateway-id "$IGW_ID" 2>/dev/null && echo "  删除 IGW" || true
fi
for sn in "$(g PUB_A)" "$(g PUB_B)" "$(g PRIV_A)"; do
  [ -n "$sn" ] && aws_cli ec2 delete-subnet --subnet-id "$sn" 2>/dev/null && echo "  删除子网 $sn" || true
done
[ -n "$VPC_ID" ] && aws_cli ec2 delete-vpc --vpc-id "$VPC_ID" 2>/dev/null && echo "  删除 VPC" || true

echo "==> destroy 完成。建议 review 控制台确认无残留。"
