terraform {
  required_version = ">= 1.10.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.37"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Partial config: reuses the landing zone's state bucket.
  # terraform init "-backend-config=backend.hcl"
  backend "s3" {
    key          = "detection-lab/terraform.tfstate"
    encrypt      = true
    use_lockfile = true
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = "aws-cloud-detection-lab"
      ManagedBy = "terraform"
      Owner     = var.owner
    }
  }
}
