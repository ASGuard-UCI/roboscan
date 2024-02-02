# Install Docker
## Add Docker's official GPG key:
sudo apt update && sudo apt upgrade -y
sudo apt install ca-certificates curl gnupg
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

## Add the repository to Apt sources:
echo \
  "deb [arch="$(dpkg --print-architecture)" signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  "$(. /etc/os-release && echo "$VERSION_CODENAME")" stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git python3 python3-pip python3-venv -y

# Create data to store PCAP files
mkdir data

# Install script dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Set up ROS docker container
docker build -t talker-listener .
docker run -d -p 11311:11311 talker-listener

# Set up sniffing service and data removal crontab
mv scapy-writer.service /etc/systemd/system
systemctl daemon-reload
systemctl start scapy-writer.service
(crontab -l; echo "0 1 * * * /usr/bin/python3 /root/ros-honeypot/remover.py") | crontab -

# Add public SSH key to new cloud server to allow rsync access
echo "Enter public SSH key: "
read publicSSHKey
echo $publicSSHKey >> ~/.ssh/authorized_keys
