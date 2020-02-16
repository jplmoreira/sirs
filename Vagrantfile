# https://www.vagrantup.com/docs/virtualbox/networking.html

Vagrant.configure("2") do |config|

  config.vm.define "central" do |central|
    central.vm.box = "ubuntu/bionic64"
	central.vm.provider "virtualbox"
    central.vm.provision "shell", path: "setup/central.sh"
   	central.vm.network "private_network", ip: "192.168.50.4"
    # central.vm.network :forwarded_port, guest:443, host:4443
   	central.vm.network "private_network", ip: "192.168.30.2", virtualbox__intnet: "sirs-central"
  end

  config.vm.define "scan" do |scan|
    scan.vm.box = "ubuntu/bionic64"
	scan.vm.provider "virtualbox"
    scan.vm.provision "shell", path: "setup/scan.sh"
   	scan.vm.network "private_network", ip: "192.168.30.3", virtualbox__intnet: "sirs-central"
	scan.vm.network "private_network", ip: "192.168.40.2", virtualbox__intnet: "sirs-scan-1"
  end

  config.vm.define "device" do |device|
    device.vm.box = "ubuntu/bionic64"
	device.vm.provider "virtualbox"
    device.vm.provision "shell", path: "setup/device.sh"
	device.vm.network "private_network", ip: "192.168.40.100", virtualbox__intnet: "sirs-scan-1"
  end
end
