# WordPress Deployment on AWS

This repository contains Terraform configurations for deploying a WordPress application in a secure, scalable, and highly available way.  It makes use of multiple AWS services eg(EC2, RDS, EFS, and Load Balancer) to distribute traffic, automatically scale the infrastructure, provide secure data storage, and ensure that the application is always accessible, even in case of hardware failure. The project is organized into modular Terraform files.

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

![Screenshot 2024-10-03 103527](https://github.com/user-attachments/assets/a4e6402f-6fb1-416f-9fb4-471ab1956291)

The image above represents a typical cloud infrastructure setup on AWS (Amazon Web Services) designed for a web application (Our Wordpress). 

- Amazon Route 53: It serves as a Domain Name System (DNS), directing user traffic to the application by converting domain names into IP addresses.
- Internet Gateway: This connects the cloud network to the internet, allowing public access to certain resources like the web servers and the load balancer.
- VPC (Virtual Private Cloud): This is an isolated network in the cloud where all the resources (servers, databases, etc.) are hosted. It has multiple subnets (smaller network segments):
- Public Subnets: Accessible from the internet, these host resources like the NAT Gateway and Load Balancer.
- Private Subnets: Not directly accessible from the internet. They are used for application servers, databases, and other internal services.
- NAT Gateway: Allows resources in the private subnets to access the internet (e.g., for software updates) while still remaining secure.
- Application Load Balancer: Distributes incoming traffic across multiple servers to ensure that no single server is overwhelmed.
- Auto Scaling Group: Automatically adjusts the number of running servers (web servers in this case) based on the current load, ensuring the application can handle traffic spikes.
- Amazon RDS (Relational Database Service): This is a managed database service. In this setup, there is a master database and a standby database for high availability (backup).
- Amazon EFS (Elastic File System): A shared file storage system that can be accessed by multiple servers. It is useful for storing files that need to be accessed by all servers in the application (e.g., user-uploaded files).
- Multi-AZ Deployment: The resources are distributed across multiple Availability Zones (us-east-1a and us-east-1b) for high availability and fault tolerance. If one data center goes down, the application can still run from the other.


## Project Structure

```
└── modules
    ├── vpc
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── sg
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── asg
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── alb
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── rds
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    ├── efs
    │   ├── outputs.tf
    │   ├── main.tf
    │   └── variables.tf
    └── keypair
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
A module in Terraform consists of a collection of .tf files, typically grouped to perform a specific task, such as setting up a VPC, creating EC2 instances, or managing databases.
Each module in thisproject handles a specific part of the infrastructure:

- VPC Module: Manages Virtual Private Cloud setup (VPC, subnets, route tables, internet gateways).
- Security Group (SG) Module: Configures security groups for EC2 instances, databases, etc.
- Auto Scaling Group (ASG) Module: Manages the setup of EC2 instances with auto-scaling policies.
- Application Load Balancer (ALB) Module: Sets up the ALB for balancing traffic across instances.
- RDS Module: Deploys a relational database service for WordPress.
- EFS Module: Provides an elastic file system for shared storage between WordPress instances.
- Key Pair Module: Manages the SSH key pair used to connect to EC2 instances.

Each module has:
- main.tf: Contains resource definitions for the module.
- variables.tf: Defines input variables specific to the module.
- outputs.tf: Exposes key information from the module (e.g., VPC ID, ALB DNS, etc.).
This modular structure promotes code reusability, organization, and flexibility for scaling or customizing the project.


### VPC Module/Main.tf
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
The above terraform code sets up a Virtual Private Cloud (VPC) in AWS with both public and private subnets, Internet access, and a NAT Gateway for routing traffic for private resources. 

- VPC Creation (aws_vpc):
A VPC with the CIDR block defined by var.vpc_cidr is created.
DNS support and DNS hostnames are enabled for resources inside the VPC.

- Internet Gateway (aws_internet_gateway):
An internet gateway is attached to the VPC, allowing resources in public subnets to communicate with the internet.

- Subnets:
Public Subnets (aws_subnet.public): Multiple public subnets are created based on the availability zones (AZs). Each subnet gets its own CIDR block, and public IPs are assigned to instances in these subnets.
Private Subnets (aws_subnet.private): Similarly, private subnets are created in the same AZs, but these do not have public IPs.

- NAT Gateway (aws_nat_gateway):
A NAT gateway is set up in each public subnet to allow private subnets to communicate with the internet securely (for things like updates or external communication) without being directly exposed.

- Elastic IPs (aws_eip):
Elastic IP addresses are created and associated with each NAT gateway to ensure they have a fixed public IP address.

- Route Tables:
  Public Route Table (aws_route_table.public): This route table routes internet-bound traffic from the public subnets to the internet gateway.
  Private Route Tables (aws_route_table.private): These route tables, one for each private subnet, direct internet-bound traffic through the NAT gateway, allowing private resources to access the internet indirectly.

- Route Table Associations:
Public and private subnets are associated with their respective route tables to define the routing rules for each subnet.

This configuration ensures that resources in public subnets can directly access the internet and resources in private subnets can access the internet through a NAT gateway without being publicly accessible themselves.



### Security group Module/Main.tf

```
resource "random_string" "suffix" {
  length  = 8
  special = false
}

resource "aws_security_group" "alb" {
  name        = "wordpress-alb-sg-${random_string.suffix.result}"  # Ensure unique name
  description = "Security group for WordPress ALB"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

    ingress {
  from_port   = 443
  to_port     = 443
  protocol    = "tcp"
  cidr_blocks = ["0.0.0.0/0"]
}

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wordpress-alb-sg"
  }
}

resource "aws_security_group" "ec2" {
  name        = "wordpress-ec2-sg"
  description = "Security group for WordPress EC2 instances"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow HTTP access
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow HTTPS access
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Allow SSH (not recommended for production)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}


resource "aws_security_group" "rds" {
  name        = "wordpress-rds-sg-${random_string.suffix.result}"
  description = "Security group for WordPress RDS"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "wordpress-rds-sg"
  }
}

resource "aws_security_group" "efs" {
  name        = "wordpress-efs-sg-${random_string.suffix.result}"
  description = "Security group for WordPress EFS"
  vpc_id      = var.vpc_id

  ingress {
    from_port       = 2049
    to_port         = 2049
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "wordpress-efs-sg"
  }
}
```

### Security group Module/variable.tf

```
variable "vpc_id" {
  description = "The ID of the VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "The CIDR block of the VPC"
  type        = string
}
```

### Security group Module/output.tf

```
output "alb_sg_id" {
  description = "The ID of the ALB security group"
  value       = aws_security_group.alb.id
}

output "ec2_sg_id" {
  description = "The ID of the EC2 security group"
  value       = aws_security_group.ec2.id
}

output "rds_sg_id" {
  description = "The ID of the RDS security group"
  value       = aws_security_group.rds.id
}

output "efs_sg_id" {
  description = "The ID of the EFS security group"
  value       = aws_security_group.efs.id
}
```

The above security group configuration creates four different security groups for managing access to various AWS resources required for a WordPress deployment: ALB, EC2, RDS, and EFS.

- ALB Security Group (aws_security_group.alb):

    Allows inbound HTTP (port 80) and HTTPS (port 443) traffic from anywhere (0.0.0.0/0).

    Allows all outbound traffic.

- The security group name is unique, using a random string suffix for uniqueness.

- EC2 Security Group (aws_security_group.ec2):

    Allows inbound HTTP (port 80), HTTPS (port 443), and SSH (port 22) traffic from anywhere.

  Allows all outbound traffic. SSH (port 22) is open, which is not recommended for production environments without proper access restrictions.

- RDS Security Group (aws_security_group.rds):
    Allows MySQL access on port 3306, but only from the EC2 security group.

  Allows all outbound traffic restricted to the CIDR block of the VPC (var.vpc_cidr).

- EFS Security Group (aws_security_group.efs):
    Allows NFS (port 2049) access from the EC2 security group for EFS.

- Allows all outbound traffic restricted to the VPC CIDR.
    These security groups ensure proper network access for the ALB, EC2, RDS, and EFS resources in the WordPress deployment. The ingress rules control incoming traffic, while the egress rules control outgoing traffic.


### Autoscaling group Module/Main.tf

```
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Launch Template for WordPress instances
resource "aws_launch_template" "wordpress" {
  name_prefix   = "wordpress-lt-"
  image_id      = data.aws_ami.amazon_linux_2.id
  instance_type = "t3.micro"
  key_name      = var.key_name

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size = 20
      volume_type = "gp2"
      delete_on_termination = true
    }
  }

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [var.ec2_sg_id]
  }

  user_data = base64encode(<<-EOF
  #!/bin/bash
  set -e  # Exit immediately if a command exits with a non-zero status.
  yum update -y
  yum install -y amazon-linux-extras
  amazon-linux-extras enable php7.4
  yum clean metadata
  yum install -y php php-mysqlnd php-fpm php-opcache
  systemctl start php-fpm
  systemctl enable php-fpm
  yum install -y httpd amazon-efs-utils
  systemctl start httpd
  systemctl enable httpd

  # Mount EFS
  mkdir -p /var/www/html
  mount -t efs ${var.efs_id}:/ /var/www/html

  # Install WordPress if not already installed
  if [ ! -f /var/www/html/wp-config.php ]; then
    wget https://wordpress.org/latest.tar.gz
    tar -xzf latest.tar.gz
    cp -r wordpress/* /var/www/html/
    rm -rf wordpress latest.tar.gz
    chown -R apache:apache /var/www/html/
    chmod -R 755 /var/www/html/

    # Configure WordPress
    cp /var/www/html/wp-config-sample.php /var/www/html/wp-config.php
    sed -i 's/database_name_here/${var.db_name}/' /var/www/html/wp-config.php
    sed -i 's/username_here/${var.db_username}/' /var/www/html/wp-config.php
    sed -i 's/password_here/${var.db_password}/' /var/www/html/wp-config.php
    sed -i 's/localhost/${split(":", var.db_endpoint)[0]}/' /var/www/html/wp-config.php
  fi

  # Ensure EFS is mounted on every boot
  echo "${var.efs_id}:/ /var/www/html efs defaults,_netdev 0 0" >> /etc/fstab

  systemctl restart httpd
EOF
  )

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "WordPress Instance"
    }
  }
}

# Auto Scaling Group for WordPress instances
resource "aws_autoscaling_group" "wordpress" {
  name                = "wordpress-asg"
  vpc_zone_identifier = var.public_subnet_ids
  target_group_arns   = [var.target_group_arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  min_size            = 2
  max_size            = 4
  desired_capacity    = 2

  launch_template {
    id      = aws_launch_template.wordpress.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "WordPress Instance"
    propagate_at_launch = true
  }
}

# Auto Scaling Policy for scaling based on CPU utilization
resource "aws_autoscaling_policy" "wordpress" {
  name                   = "wordpress-asp"
  scaling_adjustment     = 1
  adjustment_type        = "ChangeInCapacity"
  cooldown               = 300
  autoscaling_group_name = aws_autoscaling_group.wordpress.name
}

# CloudWatch Alarm for high CPU utilization
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "wordpress-high-cpu"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 120
  statistic           = "Average"
  threshold           = 80

  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.wordpress.name
  }

  alarm_description = "This metric monitors EC2 CPU utilization"
  alarm_actions     = [aws_autoscaling_policy.wordpress.arn]
}
```

### Autoscaling group Module/variable.tf

```
variable "vpc_id" {
  description = "The ID of the VPC"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs"
  type        = list(string)
}

variable "target_group_arn" {
  description = "The ARN of the target group"
  type        = string
}

variable "key_name" {
  description = "The name of the SSH key pair"
  type        = string
}

variable "efs_id" {
  description = "The ID of the EFS file system"
  type        = string
}

variable "db_name" {
  description = "The name of the WordPress database"
  type        = string
}

variable "db_username" {
  description = "The username for the WordPress database"
  type        = string
}

variable "db_password" {
  description = "The password for the WordPress database"
  type        = string
}

variable "db_endpoint" {
  description = "The endpoint of the RDS instance"
  type        = string
}

variable "ec2_sg_id" {
  description = "The ID of the EC2 security group"
  type        = string
}
```

### Autoscaling group Module/output.tf

```
output "asg_name" {
  description = "The name of the Auto Scaling Group"
  value       = aws_autoscaling_group.wordpress.name
}

output "asg_name" {
  description = "The name of the Auto Scaling Group"
  value       = aws_autoscaling_group.wordpress.name
}
```

The above Auto scaling Terraform configuration sets up an Auto Scaling Group (ASG) for WordPress instances on AWS, ensuring high availability and scalability based on CPU utilization.

- data "aws_ami" "amazon_linux_2" retrieves the latest Amazon Linux 2 AMI, which is used to launch EC2 instances

- resource "aws_launch_template" "wordpress" specifies how WordPress EC2 instances should be launched:

    Instance type is t3.micro.
  
    Uses the previously fetched Amazon Linux 2 AMI.
  
    Attaches an EBS volume for storage (20 GB, gp2 type).
  
    Includes a user_data script that installs necessary software (PHP, WordPress, EFS utils), mounts an EFS file system to /var/www/html, downloads and configures WordPress. The template also associates public IP address and attaches the security group.

- resource "aws_autoscaling_group" "wordpress" Manages the scaling of WordPress instances by using the previously defined launch template.
    Distributes instances across public subnets.
  
    Links instances to an Application Load Balancer (ALB) via the target_group_arn.
  
    Sets the scaling configuration to minimum size: 2 instances, maximum size: 4 instances, desired capacity: 2 instances.

- resource "aws_autoscaling_policy" "wordpress" Defines a scaling policy that adjusts the number of EC2 instances in the ASG based on CPU usage by increasing capacity by 1 instance when triggered and cooldown period of 300 seconds between scaling actions.

- resource "aws_cloudwatch_metric_alarm" "high_cpu" Monitors CPU utilization for the instances in the ASG. If CPU usage exceeds 80% for 2 consecutive evaluation periods, the alarm triggers. When triggered, the alarm invokes the Auto Scaling policy to add an instance.


### Application load balancer group Module/Main.tf

```
resource "aws_lb" "wordpress" {
  name               = "wordpress-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [var.alb_sg_id]
  subnets            = var.public_subnet_ids

  tags = {
    Name = "WordPress ALB"
  }
}

resource "aws_lb_target_group" "wordpress" {
  name     = "wordpress-tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = var.vpc_id

  health_check {
    path                = "/"
    healthy_threshold   = 2
    unhealthy_threshold = 10
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }
}

resource "aws_lb_listener" "wordpress" {
  load_balancer_arn = aws_lb.wordpress.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.wordpress.arn
  }
}
```

### Application load balancer group Module/variable.tf

```
variable "vpc_id" {
  description = "The ID of the VPC"
  type        = string
}

variable "public_subnet_ids" {
  description = "List of public subnet IDs"
  type        = list(string)
}

variable "alb_sg_id" {
  description = "The ID of the ALB security group"
  type        = string
}
```

### Application load balancer group Module/output.tf

```
output "alb_dns_name" {
  description = "The DNS name of the load balancer"
  value       = aws_lb.wordpress.dns_name
}

output "target_group_arn" {
  description = "The ARN of the target group"
  value       = aws_lb_target_group.wordpress.arn
}
```
The above Terraform configuration sets up an Application Load Balancer (ALB) and its associated components for a WordPress deployment:

- aws_lb (Load Balancer):

    Creates an internet-facing Application Load Balancer named "wordpress-alb."
  
    It's configured to use security groups and public subnets passed through variables (alb_sg_id and public_subnet_ids).
  
    The ALB is tagged as "WordPress ALB."

- aws_lb_target_group (Target Group) defines a target group named "wordpress-tg" for routing traffic to EC2 instances on port 80 using HTTP. The health check monitors the root path ("/"), checking for a 200 OK response. It has a healthy threshold of 2 and an unhealthy threshold of 10, with a 30-second interval.

- aws_lb_listener (Listener) configures a listener for the ALB to listen on port 80 (HTTP) and forwards incoming traffic to the "wordpress-tg" target group.
This setup ensures that incoming HTTP traffic to the ALB is forwarded to the appropriate target group, routing traffic to the WordPress application running on EC2 instances.


### Rds Module/Main.tf

```
resource "aws_db_subnet_group" "wordpress" {
  name       = "wordpress-db-subnet-group"
  subnet_ids = var.private_subnet_ids

  tags = {
    Name = "WordPress DB Subnet Group"
  }
}

resource "aws_security_group" "rds" {
  name        = "wordpress-rds-sg"
  description = "Security group for WordPress RDS"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wordpress-rds-sg"
  }
}

resource "aws_db_instance" "wordpress" {
  identifier           = "wordpress-db"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  storage_type         = "gp2"
  db_name              = var.db_name
  username             = var.db_username
  password             = var.db_password
  db_subnet_group_name = aws_db_subnet_group.wordpress.name
  vpc_security_group_ids = [aws_security_group.rds.id] 
  multi_az             = true
  skip_final_snapshot  = true

  tags = {
    Name = "WordPress DB"
  }
}
```

### Rds Module/variable.tf

```
variable "vpc_id" {
  description = "The ID of the VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type        = list(string)
}

variable "db_name" {
  description = "The name of the database"
  default     = "wordpress"
}

variable "db_username" {
  description = "Username for the database"
  default     = "admin"
}

variable "db_password" {
  description = "Password for the database"
  type        = string
}

variable "rds_sg_id" {
  description = "The ID of the RDS security group"
  type        = string
}
```

### Rds Module/output.tf

```
output "db_endpoint" {
  description = "The connection endpoint for the RDS instance"
  value       = aws_db_instance.wordpress.endpoint
}

output "db_name" {
  description = "The name of the database"
  value       = var.db_name
}
```

### Efs Module/main.tf

```
resource "aws_security_group" "efs" {
  name        = "wordpress-efs-sg"
  description = "Security group for WordPress EFS"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 2049
    to_port     = 2049
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "wordpress-efs-sg"
  }
}

resource "aws_efs_file_system" "wordpress_efs" {
  creation_token = "wordpress-efs"
  encrypted      = true

  tags = {
    Name = "WordPress EFS"
  }
}


resource "aws_efs_mount_target" "wordpress" {
  count           = length(var.private_subnet_ids)
  file_system_id  = aws_efs_file_system.wordpress_efs.id
  subnet_id       = var.private_subnet_ids[count.index]
  security_groups = [var.efs_sg_id]
}
```

### Efs Module/variable.tf

```
variable "vpc_id" {
  description = "The ID of the VPC"
  type        = string
}

variable "private_subnet_ids" {
  description = "List of private subnet IDs"
  type        = list(string)
}

variable "efs_sg_id" {
  description = "The ID of the EFS security group"
  type        = string
}
```

### Efs Module/output.tf

```
output "efs_id" {
  value = aws_efs_file_system.wordpress_efs.id
}
```

### keypair Module/main.tf

```
data "aws_key_pair" "existing" {
  key_name = var.key_name
}
```

### keypair Module/variable.tf

```
variable "key_name" {
  description = "The name of the SSH key pair"
  type        = string
}

variable "public_key_path" {
  description = "Path to the public key file"
  type        = string
}
```

### keypair Module/output.tf

```
output "key_pair_id" {
  value = data.aws_key_pair.existing.key_pair_id
}

output "key_name" {
  value = data.aws_key_pair.existing.key_name
}
```
## Root file

### Main.tf

```
provider "aws" {
  region = "us-east-1"
}

module "vpc" {
  source = "./modules/vpc"
}

module "keypair" {
  source          = "./modules/keypair"
  key_name        = var.key_name
  public_key_path = var.public_key_path
}

module "sg" {
  source   = "./modules/sg"
  vpc_id   = module.vpc.vpc_id
  vpc_cidr = module.vpc.vpc_cidr
}

module "rds" {
  source              = "./modules/rds"
  vpc_id              = module.vpc.vpc_id
  private_subnet_ids  = module.vpc.private_subnet_ids
  db_name             = var.db_name
  db_username         = var.db_username
  db_password         = var.db_password
  rds_sg_id           = module.sg.rds_sg_id  # Correctly reference the output here
}

module "efs" {
  source              = "./modules/efs"
  vpc_id              = module.vpc.vpc_id
  private_subnet_ids  = module.vpc.private_subnet_ids
  efs_sg_id           = module.sg.efs_sg_id
}

module "alb" {
  source             = "./modules/alb"
  vpc_id             = module.vpc.vpc_id
  public_subnet_ids  = module.vpc.public_subnet_ids
  alb_sg_id          = module.sg.alb_sg_id
}

module "asg" {
  source             = "./modules/asg"
  vpc_id             = module.vpc.vpc_id
  public_subnet_ids  = module.vpc.public_subnet_ids
  target_group_arn   = module.alb.target_group_arn
  key_name           = module.keypair.key_name
  db_endpoint        = module.rds.db_endpoint
  efs_id             = module.efs.efs_id
  ec2_sg_id          = module.sg.ec2_sg_id
  db_name            = var.db_name
  db_username        = var.db_username
  db_password        = var.db_password
}

output "alb_dns_name" {
  value = module.alb.alb_dns_name
}
```

### variable.tf

```
variable "db_password" {
  description = "Password for the database"
  type        = string
}

variable "key_name" {
  description = "The name of the SSH key pair"
  type        = string
}

variable "public_key_path" {
  description = "Path to the public key file"
  type        = string
}

variable "db_name" {
  description = "The name of the WordPress database"
  type        = string
}

variable "db_username" {
  description = "The username for the WordPress database"
  type        = string
}

variable "db_endpoint" {
  description = "The endpoint of the RDS instance"
  type        = string
}
```

### Terrafrom.tfvars

```
db_password     = "admin3999"  # Replace with your actual DB password
key_name        = "Test_keypair"      # Replace with your actual key pair name
public_key_path = "C:/Users/lenovo/.ssh/id_ed25519.pub"  # Replace with the path to your public key file
db_name         = "WordPress"      # Replace with your actual DB name
db_username     = "admin"  # Replace with your actual DB username
db_endpoint = "wordpress-db.c7es2eiwum1i.us-east-1.rds.amazonaws.com"
```

The two image below show our project setup and file structure, each modules containing all the code we stated earlier

![Screenshot 2024-10-17 063935](https://github.com/user-attachments/assets/f9d43ec3-0d0a-4b36-8359-afb7f2e1aa9b)

![Screenshot 2024-10-17 064054](https://github.com/user-attachments/assets/195370ec-0b4f-4a1e-bf48-f30da94a62ce)

## Executing the project

1. First we initialiaze terraform by running:

```
Terraform init
```

The above command will initialize terraform by downloading/installing the tfstate file.. these files are needed for the smooth operation of our infrastructure configuration

2. We are also going:

```
Terraform validate
```
This command helps make sure our configuration codes setup is valid and void of syntax errors and internal consistency. It ensures that the Terraform configuration is syntactically correct and that all references and expressions are valid. This command does not interact with any cloud provider's APIs or attempt to provision any resources; it only performs static analysis of the configuration files.

![Screenshot 2024-10-17 075052](https://github.com/user-attachments/assets/61cb8ced-a452-462e-adef-3d8d3d5eacd2)

The above pictures show our terraform initialized successfully and all our configurations were also valid. we are good to go to the next stage.

3. Now we run:

```
Terraform plan
```
This is a command in Terraform that creates an execution plan, showing what actions Terraform will take to create, update, or delete infrastructure resources to reach the desired state specified in the configuration files. It compares the current state of the infrastructure (stored in the Terraform state file) with the desired state defined in the configuration files. It gives you a chance to review the planned changes before making any actual modifications to the infrastructure. This can help prevent mistakes or unintended consequences.

![Screenshot 2024-10-17 075256](https://github.com/user-attachments/assets/a5b8f007-5949-402c-bf8f-20226c2d33ad)

The above image is the result of our terraform plan which shows the number of resources that are going to be created. we are setting up 38 resources, so we only get to see the end resource because they are so much to be captured in one single shot.

4. The last command to execute our configuration will be:

```
Terraform apply
```
Terrafrom appl is a command used in Terraform to execute the changes defined in the Terraform configuration files and the execution plan. It applies the changes to the infrastructure to achieve the desired state described in your Terraform configuration.

![Screenshot 2024-09-06 083615](https://github.com/user-attachments/assets/83d83783-8506-4b16-bcfe-ac3e06b58687)

In the image above a resource in our userdata was missing, after updating the userdata script, we ran our Terraform apply again and everything was successful.

## Result

The result of our configuration which is WordPress application is shown below

![Screenshot 2024-09-30 061424](https://github.com/user-attachments/assets/a6f326ff-480d-4c9e-ae4a-a06b0b22dff2)
