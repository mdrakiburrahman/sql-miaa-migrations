resource "azurerm_network_interface" "example" {
  name                = "${var.prefix}-nic"
  location            = var.resource_group_location
  resource_group_name = var.resource_group_name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = var.subnet_id
    private_ip_address_allocation = "Static" // Static because these are domain controllers
    private_ip_address            = var.private_ip
  }

  tags = var.tags
}

resource "azurerm_windows_virtual_machine" "example" {
  name                = "${var.prefix}-vm"
  resource_group_name = var.resource_group_name
  location            = var.resource_group_location
  size                = var.vm_size
  admin_username      = var.user_name
  admin_password      = var.user_password
  network_interface_ids = [
    azurerm_network_interface.example.id,
  ]

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Standard_LRS"
  }

  source_image_reference {
    publisher = var.vm_image_publisher
    offer     = var.vm_image_offer
    sku       = var.vm_image_sku
    version   = "latest"
  }

  tags = var.tags
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "example" {
  virtual_machine_id = azurerm_windows_virtual_machine.example.id
  location           = var.resource_group_location
  enabled            = true

  daily_recurrence_time = "0100"
  timezone              = "Eastern Standard Time"

  notification_settings {
    enabled = false
  }

  tags = var.tags
}
