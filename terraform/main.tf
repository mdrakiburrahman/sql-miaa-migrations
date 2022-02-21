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

  source              = "./modules/vnet-module" # My local fork from https://github.com/Azure/terraform-azurerm-vnet
  vnet_name           = var.vnet_name
  resource_group_name = azurerm_resource_group.sql_migration.name
  address_space       = ["192.168.0.0/16"]
  subnet_prefixes     = ["192.168.0.0/24", "192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.48.0/21", "192.168.144.64/27"]
  subnet_names        = ["FG-DC", "MAPLE-DC", "FG-SQL", "MAPLE-SQL", "AKS", "AzureBastionSubnet"]
  dns_servers         = ["192.168.0.4", "192.168.1.4", "168.63.129.16"] # The first IPs in FG and MAPLE subnets, we will statically assign these to the VMs

  tags = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# BASTION FOR REMOTE DESKTOP
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_public_ip" "bastion_pip" {
  depends_on          = [azurerm_resource_group.sql_migration]
  name                = "bastion-pip"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = var.tags
}

resource "azurerm_bastion_host" "bastion" {
  depends_on          = [module.vnet]
  name                = "bastion"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                 = "configuration"
    subnet_id            = lookup(module.vnet.vnet_subnets_name_id, "AzureBastionSubnet")
    public_ip_address_id = azurerm_public_ip.bastion_pip.id
  }

  tags = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# DOMAIN CONTROLLERS
# ---------------------------------------------------------------------------------------------------------------------
# FG-DC-1
module "fg_dc_1" {
  depends_on = [module.vnet]

  source                  = "./modules/vm-module" # Local path to VM module
  prefix                  = "FG-DC-1"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-DC")
  private_ip              = "192.168.0.4"
  user_password           = var.VM_USER_PASSWORD

  tags = var.tags
}
# FG-DC-2
module "fg_dc_2" {
  depends_on = [module.vnet]

  source                  = "./modules/vm-module" # Local path to VM module
  prefix                  = "FG-DC-2"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-DC")
  private_ip              = "192.168.0.5"
  user_password           = var.VM_USER_PASSWORD

  tags = var.tags
}
# MAPLE-DC-1
module "maple_dc_1" {
  depends_on = [module.vnet]

  source                  = "./modules/vm-module" # Local path to VM module
  prefix                  = "MAPLE-DC-1"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "MAPLE-DC")
  private_ip              = "192.168.1.4"
  user_password           = var.VM_USER_PASSWORD

  tags = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# SQL SERVERS
# ---------------------------------------------------------------------------------------------------------------------
# 2012
module "sql_2012" {
  depends_on = [module.vnet]

  source                  = "./modules/sql-module"
  prefix                  = "FG-SQL-2012"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-SQL")
  user_password           = var.VM_USER_PASSWORD
  vm_image_publisher      = "MicrosoftSQLServer"
  vm_image_offer          = "SQL2012SP4-WS2012R2"
  vm_image_sku            = "Enterprise"

  tags = var.tags
}
# 2014
module "sql_2014" {
  depends_on = [module.vnet]

  source                  = "./modules/sql-module"
  prefix                  = "FG-SQL-2014"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-SQL")
  user_password           = var.VM_USER_PASSWORD
  vm_image_publisher      = "MicrosoftSQLServer"
  vm_image_offer          = "sql2014sp3-ws2012r2"
  vm_image_sku            = "enterprise"

  tags = var.tags
}
# 2016
module "sql_2016" {
  depends_on = [module.vnet]

  source                  = "./modules/sql-module"
  prefix                  = "FG-SQL-2016"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-SQL")
  user_password           = var.VM_USER_PASSWORD
  vm_image_publisher      = "MicrosoftSQLServer"
  vm_image_offer          = "sql2016sp3-ws2019"
  vm_image_sku            = "enterprise"

  tags = var.tags
}
# 2017
module "sql_2017" {
  depends_on = [module.vnet]

  source                  = "./modules/sql-module"
  prefix                  = "MAPLE-SQL-2017"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "MAPLE-SQL")
  user_password           = var.VM_USER_PASSWORD
  vm_image_publisher      = "MicrosoftSQLServer"
  vm_image_offer          = "sql2017-ws2019"
  vm_image_sku            = "enterprise"

  tags = var.tags
}
# 2019
module "sql_2019" {
  depends_on = [module.vnet]

  source                  = "./modules/sql-module"
  prefix                  = "MAPLE-SQL-2019"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "MAPLE-SQL")
  user_password           = var.VM_USER_PASSWORD
  vm_image_publisher      = "MicrosoftSQLServer"
  vm_image_offer          = "sql2019-ws2019"
  vm_image_sku            = "enterprise"

  tags = var.tags
}
# 2022
module "sql_2022" {
  depends_on = [module.vnet]

  source                  = "./modules/vm-module"
  prefix                  = "FG-SQL-2022"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-SQL")
  private_ip              = "192.168.2.30" // We pick a private IP address that is not in use
  user_password           = var.VM_USER_PASSWORD
  vm_image_publisher      = "MicrosoftWindowsServer"
  vm_image_offer          = "WindowsServer"
  vm_image_sku            = "2022-datacenter" // We will install the SQL 2022 CTP binary by hand as it is not available as an Azure Marketplace image at time of writing

  tags = var.tags
}
# ---------------------------------------------------------------------------------------------------------------------
# AKS - WITH CNI
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_kubernetes_cluster" "aks" {
  depends_on = [module.vnet]

  name                = "aks-cni"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name
  dns_prefix          = "akscni"

  default_node_pool {
    name                = "agentpool"
    node_count          = 3
    vm_size             = "Standard_DS3_v2"
    type                = "VirtualMachineScaleSets"
    enable_auto_scaling = true
    min_count           = 1
    max_count           = 3

    # Required for advanced networking
    vnet_subnet_id = lookup(module.vnet.vnet_subnets_name_id, "AKS")
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin     = "azure"
    load_balancer_sku  = "standard"
    dns_service_ip     = "192.168.64.10"
    docker_bridge_cidr = "172.17.0.1/16"
    service_cidr       = "192.168.64.0/19"
    network_policy     = "azure"
  }

  lifecycle {
    ignore_changes = [
      # Ignore changes to nodes because we have autoscale enabled
      default_node_pool[0].node_count
    ]
  }

  tags = var.tags
}
