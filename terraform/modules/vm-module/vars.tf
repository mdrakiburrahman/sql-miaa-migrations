# ---------------------------------------------------------------------------------------------------------------------
# REQUIRED PARAMETERS
# You must provide a value for each of these parameters.
# ---------------------------------------------------------------------------------------------------------------------

variable "prefix" {
  description = "The prefix which should be used for all resources in this example"
  type        = string
}

variable "resource_group_location" {
  description = "The location in which the deployment is taking place"
  type        = string
}

variable "resource_group_name" {
  description = "Deployment RG name"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID in which to deploy the NIC"
  type        = string
}

variable "private_ip" {
  description = "Private IP address to assign to the NIC"
  type        = string
}

variable "tags" {
  type        = map(string)
  description = "A map of the tags to use on the resources that are deployed with this module."
}

# ---------------------------------------------------------------------------------------------------------------------
# OPTIONAL PARAMETERS
# These parameters have reasonable defaults.
# ---------------------------------------------------------------------------------------------------------------------

variable "vm_size" {
  description = "Size of the VM to create"
  type        = string
  default     = "Standard_D4s_v3"
}

variable "vm_image_publisher" {
  description = "Image Publisher"
  type        = string
  default     = "MicrosoftWindowsServer"
}

variable "vm_image_offer" {
  description = "Image Offer"
  type        = string
  default     = "WindowsServer"
}

variable "vm_image_sku" {
  description = "Image of the VM to create"
  type        = string
  default     = "2019-Datacenter"
}

variable "user_name" {
  description = "Local username"
  type        = string
  default     = "boor"
}

variable "user_password" {
  description = "Local username"
  type        = string
  default     = "P@s5w0rd123!!"
}
