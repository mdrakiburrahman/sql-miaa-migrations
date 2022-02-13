# ----------------------------------------------------------------------------------------------------------------------
# REQUIRE A SPECIFIC TERRAFORM VERSION OR HIGHER
# ----------------------------------------------------------------------------------------------------------------------
terraform {
  required_version = "~> 1.0"
  required_providers {
    azurerm = "~> 2.62.1"
  }
}

# ----------------------------------------------------------------------------------------------------------------------
# AZURE PROVIDER
# ----------------------------------------------------------------------------------------------------------------------
provider "azurerm" {
  subscription_id = var.SPN_SUBSCRIPTION_ID
  client_id       = var.SPN_CLIENT_ID
  client_secret   = var.SPN_CLIENT_SECRET
  tenant_id       = var.SPN_TENANT_ID
  features {}
}
