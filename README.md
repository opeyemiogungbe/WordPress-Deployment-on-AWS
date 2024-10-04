# WordPress Deployment on AWS

This repository contains Terraform configurations for deploying a WordPress application on AWS using various AWS services, including EC2, RDS, EFS, and Load Balancer, organized into modular Terraform files.

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture Diagram](#architecture-diagram)
3. [Modules](#modules)
    - [VPC Module](#vpc-module)
    - [Security Group Module](#security-group-module)
    - [Key Pair Module](#key-pair-module)
    - [Auto Scaling Group Module](#auto-scaling-group-module)
    - [EFS Module](#efs-module)
    - [RDS Module](#rds-module)
    - [ALB Module](#alb-module)
4. [Root Configuration](#root-configuration)
5. [Commands Used](#commands-used)
6. [License](#license)

## Project Overview
The image below shows our project's graphical architecture. Our traffic starts from  1. Engineers (working on the servers and some configuration/troubleshooting) and 2. Customers/Users will be routed through many layers throur automates the deployment of a WordPress website on AWS infrastructure. The infrastructure is set up using Terraform modules, promoting reusability and maintainability



## Project Structure
```
└── modules
    ├── efs
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── asg
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── keypair
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── rds
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── alb
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    └── sg
        ├── outputs.tf
        ├── main.tf
        └── variables.tf
Root
├── main.tf
├── variables.tf
├── outputs.tf
└── terraform.tfvars
```

## Modules

### VPC Module/Main.tf

![Screenshot 2024-10-03 103527](https://github.com/user-attachments/assets/c18ee186-75a5-45cf-9d9a-8d8ea24fdb6b)


```
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "wordpress-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "wordpress-igw"
  }
}

resource "aws_subnet" "public" {
  count                   = length(var.availability_zones)
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "private" {
  count             = length(var.availability_zones)
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + length(var.availability_zones))
  availability_zone = var.availability_zones[count.index]

  tags = {
    Name = "private-subnet-${count.index + 1}"
  }
}

resource "aws_nat_gateway" "main" {
  count         = length(var.availability_zones)
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id

  tags = {
    Name = "nat-gateway-${count.index + 1}"
  }
}

resource "aws_eip" "nat" {
  count = length(var.availability_zones)
  domain = "vpc"

  tags = {
    Name = "nat-eip-${count.index + 1}"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "public-route-table"
  }
}

resource "aws_route_table" "private" {
  count  = length(var.availability_zones)
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.main[count.index].id
  }

  tags = {
    Name = "private-route-table-${count.index + 1}"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(var.availability_zones)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table_association" "private" {
  count          = length(var.availability_zones)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}
```

### VPC Module/Variable.tf

```
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}
```

### VPC Module/output.tf

```
output "vpc_id" {
  description = "The ID of the VPC"
  value       = aws_vpc.main.id
}

output "public_subnet_ids" {
  description = "List of public subnet IDs"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "List of private subnet IDs"
  value       = aws_subnet.private[*].id
}

output "vpc_cidr" {
  description = "The CIDR block of the VPC"
  value       = aws_vpc.main.cidr_block
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}
```
