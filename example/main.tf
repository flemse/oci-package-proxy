terraform {
  required_providers {
    aws = {
      source  = "localhost:8080/novus/applicationmanagement"
      version = "0.0.10"
    }
  }
}