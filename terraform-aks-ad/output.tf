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

output "rdp_pip" {
  description = "IP Address of DC"
  value       = azurerm_public_ip.rdp_pip.ip_address
}
