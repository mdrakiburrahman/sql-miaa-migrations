# ---------------------------------------------------------------------------------------------------------------------
# ENVIRONMENT VARIABLES
# Define these secrets as environment variables
# ---------------------------------------------------------------------------------------------------------------------

variable "SPN_SUBSCRIPTION_ID" {
  description = "Azure Subscription ID"
  type        = string
}

variable "SPN_CLIENT_ID" {
  description = "Azure service principal name"
  type        = string
}

variable "SPN_CLIENT_SECRET" {
  description = "Azure service principal password"
  type        = string
}

variable "SPN_TENANT_ID" {
  description = "Azure tenant ID"
  type        = string
}

variable "VM_USER_PASSWORD" {
  description = "VM Local user password"
  type        = string
}

# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

# TBD

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------

variable "resource_group_name" {
  description = "Deployment RG name"
  type        = string
  default     = "raki-sql-to-miaa-migration-rg"
}

variable "resource_group_location" {
  description = "The location in which the deployment is taking place"
  type        = string
  default     = "eastus"
}

variable "tags" {
  type        = map(string)
  description = "A map of the tags to use on the resources that are deployed with this module."

  default = {
    Source                                                                     = "terraform"
    Owner                                                                      = "Raki"
    Project                                                                    = "SQL Server Migration to MIAA"
    azsecpack                                                                  = "nonprod"
    "platformsettings.host_environment.service.platform_optedin_for_rootcerts" = "true"
  }
}

variable "vnet_name" {
  description = "Name of Azure VNET"
  type        = string
  default     = "vnet"
}
