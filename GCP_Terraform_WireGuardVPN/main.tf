provider "google" {
  # Change to your project id
  project = "neon-semiotics-468209-j3"  
  region  = "us-central1"
  zone    = "us-central1-c"
}

# Generate SSH key pair
resource "tls_private_key" "ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "google_compute_instance" "vm_instance" {
  name         = "ieong-terraform-instance"
  machine_type = "e2-micro"

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/ubuntu-2204-lts"
    }
  }

  network_interface {
    # A default network is created for all GCP projects
    network = google_compute_network.vpc_network.id
    access_config {
    }
  }

  #startup script to install Docker and WireGuard VPN
  metadata = {
    ssh-keys = "ubuntu:${tls_private_key.ssh_key.public_key_openssh}"
    startup-script = <<-EOF
      #!/bin/bash
      apt-get update
      apt-get install -y ca-certificates curl gnupg lsb-release

      install -m 0755 -d /etc/apt/keyrings
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
      chmod a+r /etc/apt/keyrings/docker.gpg

      echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

      apt-get update
      apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

      systemctl enable docker
      systemctl start docker

      # Get the external IP address
      EXTERNAL_IP=$(curl -s ifconfig.me)
      
      # Get the HASH Password
      # Change the password to your own
      # Ex. "ieong000"
      HASH=$(docker run --rm ghcr.io/wg-easy/wg-easy:14 node -e "const bcrypt = require('bcryptjs'); const hash = bcrypt.hashSync('ieong000', 10); console.log(hash);")

      # install and run WireGuard VPN
      docker run -d \
      --name=wg-easy \
      -e WG_HOST=$EXTERNAL_IP \
      -e PASSWORD_HASH="$HASH" \
      -e WG_DEFAULT_DNS=8.8.8.8,8.8.4.4 \
      -v ~/.wg-easy:/etc/wireguard \
      -p 51820:51820/udp \
      -p 51821:51821/tcp \
      --cap-add=NET_ADMIN \
      --cap-add=SYS_MODULE \
      --sysctl="net.ipv4.conf.all.src_valid_mark=1" \
      --sysctl="net.ipv4.ip_forward=1" \
      --restart unless-stopped \
      ghcr.io/wg-easy/wg-easy

      echo "INSTALL_DONE" > /var/log/install_done


    EOF
  }
  


}


# Wait for Docker installation to complete before marking instance as ready
resource "null_resource" "wait_for_docker" {
  depends_on = [google_compute_instance.vm_instance]

  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      user        = "ubuntu"
      host        = google_compute_instance.vm_instance.network_interface[0].access_config[0].nat_ip
      private_key = tls_private_key.ssh_key.private_key_pem
    }

    inline = [
      # It could take 10 min
      "until test -f /var/log/install_done; do echo 'Waiting for installation...'; sleep 10; done"

    ]
  }
}


resource "google_compute_network" "vpc_network" {
  name                    = "ieong-terraform-network"
  auto_create_subnetworks = "true"
}

resource "google_compute_firewall" "allow_ingress" {
  name    = "ieong-allow-ingress"
  network = google_compute_network.vpc_network.id

  allow {
    protocol = "tcp"
    ports    = ["22", "51821"]
  }

  allow {
    protocol = "udp"
    ports    = ["51820"]
  }

  source_ranges = ["0.0.0.0/0"]  # Restrict this to specific IPs for better security
  direction     = "INGRESS"
}

# Output the public key (for reference)
output "public_key" {
  value = tls_private_key.ssh_key.public_key_openssh
}

# Output the instance's public IP
# Use this ip to connect to the WireGuard VPN
# Ex. X.X.X.X:51821 
output "instance_ip" {
  value = google_compute_instance.vm_instance.network_interface[0].access_config[0].nat_ip
}