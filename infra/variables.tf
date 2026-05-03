variable "aws_region" {
  description = "AWS region to deploy into"
  type        = string
  default     = "ap-south-1"  # Mumbai — close to India
}

variable "cluster_name" {
  description = "EKS cluster name"
  type        = string
  default     = "tcs-ion-security-platform"
}

variable "node_instance_type" {
  description = "EC2 instance type for general worker nodes"
  type        = string
  default     = "m5.xlarge"
}

variable "common_tags" {
  description = "Tags applied to all resources"
  type        = map(string)
  default = {
    Project     = "TCS-iON-AIP225"
    Environment = "development"
    ManagedBy   = "terraform"
  }
}
