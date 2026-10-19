#!/usr/bin/env bash
# Deploy Aegis-SOC to a single EC2 instance, built from the public repo.
#
#   REGION=us-east-1 ./deploy-aws.sh
#
# Requires an authenticated aws CLI (works from AWS CloudShell as-is).
# No Docker needed locally: the instance builds the image itself via user-data.
#
# Cost (verify in your account): t3.micro on-demand is roughly US$0.0104/hr
# (~$7.60/month) plus a few cents of EBS. Free tier covers 750 hrs/month of
# t3.micro for the first 12 months of an account. Terminate when done — see the
# teardown line printed at the end.
set -euo pipefail

REGION="${REGION:-us-east-1}"
INSTANCE_TYPE="${INSTANCE_TYPE:-t3.micro}"
NAME="${NAME:-aegis-soc}"
REPO="${REPO:-https://github.com/Rhack-INDIA/aegis-soc.git}"
SG_NAME="${NAME}-sg"
KEY_NAME="${NAME}-key"
KEY_PATH="${KEY_PATH:-$HOME/.ssh/${KEY_NAME}.pem}"

say() { printf "\n\033[1;36m==> %s\033[0m\n" "$*"; }

say "Checking credentials"
aws sts get-caller-identity --output table || {
  echo "aws CLI is not authenticated. Run 'aws configure' or use AWS CloudShell." >&2
  exit 1
}

say "Default VPC"
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
if [ "$VPC_ID" = "None" ] || [ -z "$VPC_ID" ]; then
  echo "No default VPC in $REGION. Create one or pass a subnet manually." >&2
  exit 1
fi
echo "vpc: $VPC_ID"

say "Security group (8080 open for the demo URL)"
SG_ID=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters Name=group-name,Values="$SG_NAME" Name=vpc-id,Values="$VPC_ID" \
  --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || true)
if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
  SG_ID=$(aws ec2 create-security-group --region "$REGION" \
    --group-name "$SG_NAME" --description "Aegis-SOC demo" --vpc-id "$VPC_ID" \
    --query 'GroupId' --output text)
  aws ec2 authorize-security-group-ingress --region "$REGION" --group-id "$SG_ID" \
    --protocol tcp --port 8080 --cidr 0.0.0.0/0 >/dev/null
fi
echo "sg: $SG_ID"

say "Key pair ($KEY_PATH)"
if ! aws ec2 describe-key-pairs --region "$REGION" --key-names "$KEY_NAME" >/dev/null 2>&1; then
  aws ec2 create-key-pair --region "$REGION" --key-name "$KEY_NAME" \
    --query 'KeyMaterial' --output text > "$KEY_PATH"
  chmod 600 "$KEY_PATH"
  echo "created $KEY_PATH"
else
  echo "key pair already exists (private key not re-downloadable; SSM/console still work)"
fi

say "Launching $INSTANCE_TYPE"
AMI=$(aws ssm get-parameters --region "$REGION" \
  --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
  --query 'Parameters[0].Value' --output text)

USER_DATA=$(cat <<CLOUDINIT
#!/bin/bash
set -euxo pipefail
exec > >(tee -a /var/log/aegis-boot.log) 2>&1

dnf install -y docker git
systemctl enable --now docker

git clone ${REPO} /opt/aegis
cd /opt/aegis
docker build -t aegis-soc:latest .

mkdir -p /opt/aegis-data
docker run -d --name aegis --restart unless-stopped \
  -p 8080:8080 \
  -e STORE=sqlite -e SQLITE_PATH=/data/aegis.db -e AUTO_TRIAGE=1 \
  -e APPLY_BLOCKS=simulated \
  -v /opt/aegis-data:/data \
  aegis-soc:latest

# Public HTTPS without opening any inbound port (belt and braces next to 8080)
curl -sL -o /usr/local/bin/cloudflared \\
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x /usr/local/bin/cloudflared
nohup cloudflared tunnel --url http://localhost:8080 --no-autoupdate \\
  > /var/log/cloudflared.log 2>&1 &

sleep 25
URL=\$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' /var/log/cloudflared.log | head -1)
echo "\$URL" > /var/log/aegis-url.txt
echo "AEGIS_TUNNEL=\$URL" > /dev/ttyS0 || true
echo "AEGIS_READY" > /dev/ttyS0 || true
CLOUDINIT
)

INSTANCE_ID=$(aws ec2 run-instances --region "$REGION" \
  --image-id "$AMI" --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" --security-group-ids "$SG_ID" \
  --user-data "$USER_DATA" \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=12,VolumeType=gp3}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${NAME}}]" \
  --query 'Instances[0].InstanceId' --output text)
echo "instance: $INSTANCE_ID"

say "Waiting for running state"
aws ec2 wait instance-running --region "$REGION" --instance-ids "$INSTANCE_ID"
IP=$(aws ec2 describe-instances --region "$REGION" --instance-ids "$INSTANCE_ID" \
  --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

cat <<EOF

Instance : $INSTANCE_ID
Public IP: $IP

First boot builds the image on the instance (~3-5 min). Then:

  # direct (port 8080 opened by the security group)
  curl -s http://$IP:8080/api/health

  # tunnel URL (public HTTPS, no inbound port needed)
  aws ec2 get-console-output --region $REGION --instance-id $INSTANCE_ID --latest \\
    | grep -oE 'https://[a-z0-9-]+\\.trycloudflare\\.com' | head -1

  # logs if something failed
  aws ec2 get-console-output --region $REGION --instance-id $INSTANCE_ID --latest | tail -50

Teardown when the demo is over (stops all charges):

  aws ec2 terminate-instances --region $REGION --instance-ids $INSTANCE_ID
EOF
