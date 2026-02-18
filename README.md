# Shinkai-Shoujo
Agentless AWS IAM privilege analysis via OpenTelemetry. Finds unused permissions by correlating OTel traces with IAM policies, then generates Terraform to remove them. Zero deployment, zero agents—just point at your existing telemetry and get least-privilege IAM. Stop paying $100k/year for what should be free.
