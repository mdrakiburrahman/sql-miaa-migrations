resource "azurerm_network_interface" "example" {
  name                = "${var.prefix}-nic"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Dynamic" // Dynamic on purpose
  }

  tags = var.tags
}

resource "azurerm_virtual_machine" "example" {
  name                = "${var.prefix}-sql-vm"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]
  vm_size                       = var.vm_size
  delete_os_disk_on_termination = true

  storage_image_reference {
    publisher = var.vm_image_publisher
    offer     = var.vm_image_offer
    sku       = var.vm_image_sku
    version   = "latest"
  }

  storage_os_disk {
    name              = "${var.prefix}-sql-osdisk"
    caching           = "ReadWrite"
    create_option     = "FromImage"
    managed_disk_type = "Standard_LRS"
  }

  os_profile {
    computer_name  = var.prefix
    admin_username = var.user_name
    admin_password = var.user_password
  }

  os_profile_windows_config {
    provision_vm_agent = true
  }

  tags = var.tags
}

resource "azurerm_virtual_machine_extension" "example" {
  virtual_machine_id   = azurerm_virtual_machine.example.id
  name                 = "SqlIaasExtension"
  publisher            = "Microsoft.SqlServer.Management"
  type                 = "SqlIaaSAgent"
  type_handler_version = "1.2"

  settings = <<SETTINGS
  {
    "AutoTelemetrySettings": {
      "Region": "eastus"
    },
    "AutoPatchingSettings": {
      "PatchCategory": "WindowsMandatoryUpdates",
      "Enable": true,
      "DayOfWeek": "Sunday",
      "MaintenanceWindowStartingHour": "2",
      "MaintenanceWindowDuration": "60"
    },
    "KeyVaultCredentialSettings": {
      "Enable": false,
      "CredentialName": ""
    },
    "ServerConfigurationsManagementSettings": {
      "SQLConnectivityUpdateSettings": {
          "ConnectivityType": "Private",
          "Port": "1433",
          "SqlAuthenticationEnabled": true
      },
      "SQLWorkloadTypeUpdateSettings": {
          "SQLWorkloadType": "GENERAL"
      },
      "AdditionalFeaturesServerConfigurations": {
          "IsRServicesEnabled": "false"
      }
    }
  }
SETTINGS

  tags = var.tags
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "example" {
  virtual_machine_id = azurerm_virtual_machine.example.id
  location           = var.resource_group_location
  enabled            = true

  daily_recurrence_time = "2300"
  timezone              = "Eastern Standard Time"

  notification_settings {
    enabled = false
  }

  tags = var.tags
}
