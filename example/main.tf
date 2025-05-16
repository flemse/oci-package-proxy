terraform {
  required_providers {
    applicationmanagement = {
      source  = "localhost.test:8080/novus/applicationmanagement"
      version = "<= 0.3"
    }
  }
}
