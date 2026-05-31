#!/usr/bin/env bash
# 网络：VPC、2公有子网、1私有子网、IGW、NAT、路由表
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/00-config.sh"

echo "==> 01 network"

TAGSPEC() { echo "ResourceType=$1,Tags=[{Key=Project,Value=${PROJECT}},{Key=Name,Value=${PROJECT}-$2}]"; }

# VPC
VPC_ID=$(aws_cli ec2 create-vpc --cidr-block "$VPC_CIDR" \
  --tag-specifications "$(TAGSPEC vpc vpc)" \
  --query 'Vpc.VpcId' --output text)
aws_cli ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames '{"Value":true}'
state_set VPC_ID "$VPC_ID"

# 两个 AZ
AZ_A=$(aws_cli ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)
AZ_B=$(aws_cli ec2 describe-availability-zones --query 'AvailabilityZones[1].ZoneName' --output text)

# 子网
PUB_A=$(aws_cli ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$PUBLIC_SUBNET_A_CIDR" \
  --availability-zone "$AZ_A" --tag-specifications "$(TAGSPEC subnet public-a)" \
  --query 'Subnet.SubnetId' --output text); state_set PUB_A "$PUB_A"
PUB_B=$(aws_cli ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$PUBLIC_SUBNET_B_CIDR" \
  --availability-zone "$AZ_B" --tag-specifications "$(TAGSPEC subnet public-b)" \
  --query 'Subnet.SubnetId' --output text); state_set PUB_B "$PUB_B"
PRIV_A=$(aws_cli ec2 create-subnet --vpc-id "$VPC_ID" --cidr-block "$PRIVATE_SUBNET_A_CIDR" \
  --availability-zone "$AZ_A" --tag-specifications "$(TAGSPEC subnet private-a)" \
  --query 'Subnet.SubnetId' --output text); state_set PRIV_A "$PRIV_A"

# IGW
IGW_ID=$(aws_cli ec2 create-internet-gateway --tag-specifications "$(TAGSPEC internet-gateway igw)" \
  --query 'InternetGateway.InternetGatewayId' --output text); state_set IGW_ID "$IGW_ID"
aws_cli ec2 attach-internet-gateway --internet-gateway-id "$IGW_ID" --vpc-id "$VPC_ID"

# NAT（需要 EIP + 放在公有子网）
EIP_ALLOC=$(aws_cli ec2 allocate-address --domain vpc \
  --tag-specifications "$(TAGSPEC elastic-ip nat-eip)" \
  --query 'AllocationId' --output text); state_set EIP_ALLOC "$EIP_ALLOC"
NAT_ID=$(aws_cli ec2 create-nat-gateway --subnet-id "$PUB_A" --allocation-id "$EIP_ALLOC" \
  --tag-specifications "$(TAGSPEC natgateway nat)" \
  --query 'NatGateway.NatGatewayId' --output text); state_set NAT_ID "$NAT_ID"
echo "  等待 NAT 可用 ..."
aws_cli ec2 wait nat-gateway-available --nat-gateway-ids "$NAT_ID"

# 公有路由表
RT_PUB=$(aws_cli ec2 create-route-table --vpc-id "$VPC_ID" \
  --tag-specifications "$(TAGSPEC route-table rt-public)" \
  --query 'RouteTable.RouteTableId' --output text); state_set RT_PUB "$RT_PUB"
aws_cli ec2 create-route --route-table-id "$RT_PUB" --destination-cidr-block 0.0.0.0/0 --gateway-id "$IGW_ID" >/dev/null
aws_cli ec2 associate-route-table --route-table-id "$RT_PUB" --subnet-id "$PUB_A" >/dev/null
aws_cli ec2 associate-route-table --route-table-id "$RT_PUB" --subnet-id "$PUB_B" >/dev/null

# 私有路由表（出网经 NAT）
RT_PRIV=$(aws_cli ec2 create-route-table --vpc-id "$VPC_ID" \
  --tag-specifications "$(TAGSPEC route-table rt-private)" \
  --query 'RouteTable.RouteTableId' --output text); state_set RT_PRIV "$RT_PRIV"
aws_cli ec2 create-route --route-table-id "$RT_PRIV" --destination-cidr-block 0.0.0.0/0 --nat-gateway-id "$NAT_ID" >/dev/null
aws_cli ec2 associate-route-table --route-table-id "$RT_PRIV" --subnet-id "$PRIV_A" >/dev/null

# 校验
aws_cli ec2 describe-vpcs --vpc-ids "$VPC_ID" >/dev/null
echo "  ✓ network done (VPC=$VPC_ID)"
