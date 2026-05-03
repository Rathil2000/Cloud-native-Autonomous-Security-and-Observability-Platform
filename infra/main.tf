# ─────────────────────────────────────────────────────────────────
# AWS Infrastructure — TCS iON AIP 225 Security Platform
# Provisions: VPC, EKS, IAM roles, S3 log archive
# Usage:
#   terraform init
#   terraform plan -var-file="terraform.tfvars"
#   terraform apply -var-file="terraform.tfvars"
# ─────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# ── Data Sources ───────────────────────────────────────────────
data "aws_availability_zones" "available" {}

# ── VPC ────────────────────────────────────────────────────────
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.7.0"

  name = "${var.cluster_name}-vpc"
  cidr = "10.0.0.0/16"

  azs             = slice(data.aws_availability_zones.available.names, 0, 3)
  private_subnets = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
  public_subnets  = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = false  # one per AZ for HA
  enable_dns_hostnames   = true
  enable_dns_support     = true

  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }

  tags = var.common_tags
}

# ── EKS Cluster ────────────────────────────────────────────────
module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "20.10.0"

  cluster_name    = var.cluster_name
  cluster_version = "1.29"

  cluster_endpoint_public_access = true

  vpc_id                   = module.vpc.vpc_id
  subnet_ids               = module.vpc.private_subnets
  control_plane_subnet_ids = module.vpc.private_subnets

  cluster_addons = {
    coredns    = { most_recent = true }
    kube-proxy = { most_recent = true }
    vpc-cni    = { most_recent = true }
    aws-ebs-csi-driver = { most_recent = true }
  }

  eks_managed_node_groups = {
    # General workloads
    general = {
      name           = "general"
      instance_types = [var.node_instance_type]
      min_size       = 2
      max_size       = 10
      desired_size   = 3
      disk_size      = 50
      labels = {
        "node-role" = "general"
      }
    }

    # ML workloads (larger instance)
    ml = {
      name           = "ml-workers"
      instance_types = ["m5.2xlarge"]
      min_size       = 1
      max_size       = 4
      desired_size   = 1
      disk_size      = 100
      labels = {
        "node-role" = "ml"
      }
      taints = [{
        key    = "node-role"
        value  = "ml"
        effect = "NO_SCHEDULE"
      }]
    }
  }

  tags = var.common_tags
}

# ── S3 Log Archive ─────────────────────────────────────────────
resource "aws_s3_bucket" "log_archive" {
  bucket = "${var.cluster_name}-log-archive-${data.aws_caller_identity.current.account_id}"
  tags   = var.common_tags
}

data "aws_caller_identity" "current" {}

resource "aws_s3_bucket_versioning" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  rule {
    id     = "tiered-storage"
    status = "Enabled"
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration { days = 365 }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "log_archive" {
  bucket = aws_s3_bucket.log_archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# ── IAM Roles ─────────────────────────────────────────────────
resource "aws_iam_role" "platform_role" {
  name = "${var.cluster_name}-platform-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = var.common_tags
}

resource "aws_iam_role_policy" "platform_policy" {
  name = "${var.cluster_name}-platform-policy"
  role = aws_iam_role.platform_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
        Resource = [aws_s3_bucket.log_archive.arn, "${aws_s3_bucket.log_archive.arn}/*"]
      }
    ]
  })
}

# ── Outputs ────────────────────────────────────────────────────
output "cluster_name"      { value = module.eks.cluster_name }
output "cluster_endpoint"  { value = module.eks.cluster_endpoint }
output "cluster_region"    { value = var.aws_region }
output "log_archive_bucket"{ value = aws_s3_bucket.log_archive.bucket }
output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${var.aws_region} --name ${var.cluster_name}"
}
