# ---------------------------------------------------------------------------------------------------------------------
# AZURE RESOURCE GROUP
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_resource_group" "aad_fog" {
  name     = var.resource_group_name
  location = var.resource_group_location
  tags     = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# AZURE VIRTUAL NETWORK
# ---------------------------------------------------------------------------------------------------------------------
module "vnet" {
  depends_on = [azurerm_resource_group.aad_fog]

  source              = "../terraform/modules/vnet-module"
  vnet_name           = var.vnet_name
  resource_group_name = azurerm_resource_group.aad_fog.name
  address_space       = ["192.168.0.0/16"]
  subnet_prefixes     = ["192.168.0.0/24", "192.168.48.0/21"]
  subnet_names        = ["FG-DC", "AKS"]
  dns_servers         = ["192.168.0.4", "168.63.129.16"]

  tags = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# DOMAIN CONTROLLERS
# ---------------------------------------------------------------------------------------------------------------------
# FG-DC-1
module "fg_dc_1" {
  depends_on = [module.vnet]

  source                  = "../terraform/modules/vm-module" # Local path to VM module
  prefix                  = "FG-DC-1"
  resource_group_location = var.resource_group_location
  resource_group_name     = var.resource_group_name
  subnet_id               = lookup(module.vnet.vnet_subnets_name_id, "FG-DC")
  private_ip              = "192.168.0.4"
  user_password           = var.VM_USER_PASSWORD
  public_ip_id            = azurerm_public_ip.rdp_pip.id
  tags                    = var.tags
}

# ---------------------------------------------------------------------------------------------------------------------
# PUBLIC IP FOR REMOTE DESKTOP
# ---------------------------------------------------------------------------------------------------------------------
resource "azurerm_public_ip" "rdp_pip" {
  depends_on          = [azurerm_resource_group.aad_fog]
  name                = "rdp-pip"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name
  allocation_method   = "Static"
  sku                 = "Standard"

  tags = var.tags
}

locals {
  my_ips = ["99.192.0.0/10", "167.192.0.0/10"] # My IPs
}

resource "azurerm_network_security_group" "nsg" {
  name                = "rdp_nsg"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "allow_rdp_sg"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "3389"
    destination_address_prefix = "*"
    source_address_prefixes    = local.my_ips
  }

  security_rule {
    name                       = "allow_tde_sg"
    priority                   = 200
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "31433"
    destination_address_prefix = "*"
    source_address_prefixes    = local.my_ips
  }

  tags = var.tags
}

resource "azurerm_network_interface_security_group_association" "association" {
  network_interface_id      = module.fg_dc_1.nic_id
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_subnet_network_security_group_association" "dc_subnet" {
  subnet_id                 = lookup(module.vnet.vnet_subnets_name_id, "FG-DC")
  network_security_group_id = azurerm_network_security_group.nsg.id
}

resource "azurerm_subnet_network_security_group_association" "aks_subnet" {
  subnet_id                 = lookup(module.vnet.vnet_subnets_name_id, "AKS")
  network_security_group_id = azurerm_network_security_group.nsg.id
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
    max_count           = 6

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
