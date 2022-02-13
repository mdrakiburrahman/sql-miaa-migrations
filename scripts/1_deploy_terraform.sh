# ---------------------------------------------------------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# For Terraform
# ---------------------------------------------------------------------------------------------------------------------
# Secret
export TF_VAR_SPN_CLIENT_ID=$spnClientId
export TF_VAR_SPN_CLIENT_SECRET=$spnClientSecret
export TF_VAR_SPN_TENANT_ID=$spnTenantId
export TF_VAR_SPN_SUBSCRIPTION_ID=$subscriptionId

# Module specific
export TF_VAR_resource_group_name='raki-sql-to-miaa-migration-test-rg'

# ---------------------------------------------------------------------------------------------------------------------
# DEPLOY TERRAFORM
# ---------------------------------------------------------------------------------------------------------------------
cd terraform
terraform init
terraform plan
terraform apply -auto-approve