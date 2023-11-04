provider "aws" {
  region = "us-west-2"
}

# Vulnerabilidad 1: Credenciales en claro en el código
resource "aws_instance" "example" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t2.micro"
  key_name      = "mi_clave"
  subnet_id     = "subnet-0bb1c79de3EXAMPLE"

  # Vulnerabilidad 2: Parámetros sensibles en texto plano
  user_data = <<-EOF
              #!/bin/bash
              echo "Clave secreta = $SECRET_KEY" >> /tmp/resultado.txt
              EOF

  tags = {
    Name = "example-instance"
  }
}

# Vulnerabilidad 3: Exposición de recursos a internet sin restricciones
resource "aws_security_group" "example" {
  name        = "example"
  description = "Allow inbound traffic"

  ingress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Vulnerabilidad 4: Uso de configuraciones inseguras
resource "aws_s3_bucket" "example" {
  bucket = "my-insecure-bucket"

  acl    = "public-read"

  website {
    index_document = "index.html"
    error_document = "error.html"
  }
}

# Vulnerabilidad 5: Falta de control de versiones
# Falta de configuración para almacenar el estado de Terraform de manera segura
terraform {
  backend "s3" {
    bucket = "tf-state-bucket"
    key    = "terraform.tfstate"
    region = "us-west-2"
  }
}
