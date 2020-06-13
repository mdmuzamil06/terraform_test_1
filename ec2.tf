//provider information!!!!!
provider "aws" {
     region   ="ap-south-1"
     profile  ="vishnu2"
}

/*
//create out private key-pairs!!!!
resource "tls_private_key" "pkey" {
  algorithm   = "RSA"
}


resource "aws_key_pair" "mykey000" {
  key_name   = "mykey000"
  public_key = "${tls_private_key.pkey.public_key_openssh}"
}
*/

//cerate security resource!!!!
resource "aws_security_group" "security-group000" {
	name        = "security-group000"
	description = "Allow TCP/HTTP/HTTPS traffic"
        //incoming traffic form HTTP/HTTPS/SSH	
	ingress {
		description = "TCP from VPC"
		from_port   = 80
		to_port     = 80
		protocol    = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
		}
	ingress {
		description = "SSH from VPC"
		from_port   = 22
		to_port     = 22
		protocol    = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
		}
	ingress {
		description = "HTTPS from VPC"
		from_port   = 443
		to_port     = 443
		protocol    = "tcp"
		cidr_blocks = ["0.0.0.0/0"]
		}
        //outgoing traffic from ports
	egress {
		from_port   = 0
		to_port     = 0
		protocol    = "-1"
		cidr_blocks = ["0.0.0.0/0"]
		}
tags = {
	Name = "security-group000"
	}
}


//Launching new EC2 instance!!!!
resource "aws_instance" "webserver" {
  ami           = "ami-0447a12f28fddb066"
  instance_type = "t2.micro"
  availability_zone = aws_ebs_volume.ebs_volume1.availability_zone
  key_name      = "mykey1"
  security_groups = ["${aws_security_group.security-group000.name}"]
  user_data = <<-EOF
                #! /bin/bash
                sudo su - root
                sudo yum install httpd -y
                sudo yum install php -y
                sudo systemctl start httpd
                sudo systemctl enable httpd
                sudo yum install git -y
                sudo setenforce 0
                EOF

  tags = {
    Name = "webserver"
  }

}



//create and attcach EBS volume!!!!
resource "aws_ebs_volume" "ebs_volume1" {
	availability_zone = "ap-south-1a"
	size              = 1
tags = {
	Name = "ebs_volume1"
	}
}


resource "aws_volume_attachment" "ebs_vol_attach" {
	device_name = "/dev/sdr"
	volume_id   = aws_ebs_volume.ebs_volume1.id
        instance_id = aws_instance.webserver.id
	force_detach = true
}


output "myinstance_ip" {
	value = aws_instance.webserver.public_ip
}


//create S3 bucket 
//1)bucket create
resource "aws_s3_bucket" "new_bucket"{
	bucket = "webpage-data-bucket"
	acl    = "private"
	tags = {
    Name = "new_bucket"
  }
}
resource "aws_s3_bucket_public_access_block" "s3type" {
  bucket = "${aws_s3_bucket.new_bucket.id}"
  block_public_acls   = false
  block_public_policy = false
}





//create cloudfront!!!!

locals {
  s3_origin_id = "myS3Origin"
}
resource "aws_cloudfront_distribution" "bucketS3_dist" {
  origin {
    domain_name = "${aws_s3_bucket.new_bucket.bucket_regional_domain_name}"
    origin_id   = "${local.s3_origin_id}"
custom_origin_config {
    http_port = 80
    https_port = 80
    origin_protocol_policy = "match-viewer"
    origin_ssl_protocols = ["TLSv1", "TLSv1.1", "TLSv1.2"] 
    }
  }
enabled = true
default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "${local.s3_origin_id}"
forwarded_values {
    query_string = false
cookies {
      forward = "none"
      }
    }
viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }
restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
viewer_certificate {
    cloudfront_default_certificate = true
  }
}
resource "null_resource" "wepip"  {
 provisioner "local-exec" {
     command = "echo  ${aws_instance.webserver.public_ip} > publicip.txt"
        }
}
//mounting
resource "null_resource" "remote"  {
depends_on = [
    aws_volume_attachment.ebs_vol_attach,
  ]
connection {
    type     = "ssh"
    user     = "ec2-user"
    private_key = file("C:/Users/Vishnu/Downloads/mykey1.pem")
    host     = aws_instance.webserver.public_ip
  }
provisioner "remote-exec" {
    inline = [
      "sudo su - root",
      "sudo mkfs.ext4  /dev/xvdr",
      "sudo mount  /dev/xvdr  /var/www/html",
      "sudo rm -rf /var/www/html/*",
      "sudo git clone https://github.com/vishnuparikh/terraform_test_1.git /var/www/html/"
    ]
  }
}




