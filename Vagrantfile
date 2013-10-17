# -*- mode: ruby -*-
# vi: set ft=ruby :

VAGRANTFILE_API_VERSION = "2"

Vagrant.configure(VAGRANTFILE_API_VERSION) do |config|
  config.vm.box = "precise32"
  config.vm.box_url = "http://files.vagrantup.com/precise32.box"
  config.vm.hostname = "backend.minion"
  config.vm.provision :puppet do |puppet|
    puppet.manifests_path = "puppet/manifests"
    puppet.module_path = "puppet/modules"
    puppet.manifest_file = "development.pp"
    puppet.options = ['--verbose']
  end
  config.vm.provider "virtualbox" do |v|
    v.customize ["modifyvm", :id, "--memory", "1024"]
  end
end

