
class system-update {
  exec { 'apt-get update':
    command => 'apt-get update',
    path => ['/usr/bin', '/bin', '/usr/sbin', '/sbin'],
  }

  $sysPackages = [ "build-essential", "libcurl4-openssl-dev" ]
  package { $sysPackages:
    ensure => "installed",
    require => Exec['apt-get update'],
  }
}

class mongodb {
  require 'system-update'

  package { "mongodb":
    ensure  => present,
  }
  service { "mongodb":
    ensure  => "running",
    require => Package["mongodb"],
  }
}

class rabbitmq {
  require 'system-update'

  package { "rabbitmq-server":
    ensure  => present,
  }
  service { "rabbitmq-server":
    ensure  => "running",
    require => Package["rabbitmq-server"],
  }
}

class { 'python':
 version       => 'system',
 dev           => true,
 virtualenv    => true,
}

class minion-backend {
  $checkout = "/vagrant"
  $virtualenv = "/home/vagrant/env"

  python::virtualenv { $virtualenv:
   ensure       => present,
   owner        => "vagrant",
   version      => "system",
  }

  exec { 'setup':
   command     => "${virtualenv}/bin/python setup.py develop",
   cwd         => $checkout,
   path        => ["${virtualenv}/bin", '/usr/bin', '/bin', '/usr/sbin', '/sbin' ],
   refreshonly => true,
   subscribe   => Python::Virtualenv[$virtualenv],
   user        => "vagrant",
  }

  Class['python'] -> Class['minion-backend']
}

include mongodb
include rabbitmq
include 'minion-backend'

