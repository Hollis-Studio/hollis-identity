terraform {
  required_version = ">= 1.5.7"

  # State holds the generated password pepper, JWT key material and DB password
  # (random_password.* / tls_private_key.jwt in main.tf). Losing it means the
  # next apply REGENERATES them, which would invalidate every stored password
  # hash. It lives in the versioned, encrypted suite state bucket alongside
  # hollis-workouts/server/terraform.tfstate, not on one workstation.
  backend "s3" {
    bucket         = "hollis-health-tf-state-prod"
    key            = "hollis-identity/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "hollis-health-tf-locks-prod"
  }

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
    # tls provider kept: RS256 key material (JWT_PRIVATE_KEY / JWT_PUBLIC_KEY)
    # is still generated and stored in Secrets Manager as unused fallback.
    # If RS256 support is dropped, remove this block and the tls_private_key
    # resource in main.tf.
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]

  default_tags {
    tags = local.tags
  }
}
