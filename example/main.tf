terraform {
  required_providers {
    applicationmanagement = {
      source  = "localhost.test:8080/novus/applicationmanagement"
      version = "<= 0.3"
    }
  }
}

module "test" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"
}

module "test2" {
  source = "terraform-aws-modules/vpc/aws"
  version = "3.14.0"
}