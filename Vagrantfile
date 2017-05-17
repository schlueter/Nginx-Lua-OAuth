$script = <<EOS
apt-get update
apt-get install -y nginx-extras lua-cjson lua-zlib
[ -e /etc/nginx/sites-available/default ] && rm /etc/nginx/sites-available/default
ln -sf /vagrant/oauth-nginx-example.conf /etc/nginx/sites-enabled/
service nginx restart
EOS

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/xenial64"
  config.vm.network "private_network", ip: "192.168.29.42"
  config.vm.provision "shell", inline: $script, privileged: true
end
