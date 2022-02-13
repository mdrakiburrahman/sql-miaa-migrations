# ----------------------------------------------------------------------------------------------------------------------
# OUTPUT DESIRED VALUES
# ----------------------------------------------------------------------------------------------------------------------
output "vnet_id" {
  value = module.vnet.vnet_id
}

output "vnet_subnet_ids" {
  description = "CIDRs of the subnets in the VNet"
  value       = module.vnet.vnet_subnets
}

output "vnet_subnets_name_id" {
  description = "CIDRs of the subnets in the VNet"
  value       = lookup(module.vnet.vnet_subnets_name_id, "FG-DC")
}

output "bastion_pip" {
  description = "IP Address of Bastion Host"
  value       = azurerm_public_ip.bastion_pip.ip_address
}
