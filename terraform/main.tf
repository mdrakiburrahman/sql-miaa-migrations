# ---------------------------------------------------------------------------------------------------------------------
# AZURE RESOURCE GROUP
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_resource_group" "sql_migration" {
  name     = var.resource_group_name
  location = var.resource_group_location
  tags     = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# AZURE VIRTUAL NETWORK
# ---------------------------------------------------------------------------------------------------------------------
module "vnet" {
  depends_on = [azurerm_resource_group.sql_migration]

  source              = "Azure/vnet/azurerm" # Pull from Terraform registry
  vnet_name           = var.vnet_name
  resource_group_name = azurerm_resource_group.sql_migration.name
  address_space       = ["192.168.0.0/16"]
  subnet_prefixes     = ["192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.48.0/21", "192.168.144.64/27"]
  subnet_names        = ["FG-DC", "MAPLE-DC", "FG-SQL", "MAPLE-SQL", "AKS", "Bastion"]

  tags = var.tags
}
