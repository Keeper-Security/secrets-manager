# spec/support/operating_systems.rb
module OperatingSystems
  SUPPORTED_OS = {
    'centos-7-x86_64' => {
      'os' => {
        'family' => 'RedHat',
        'name' => 'CentOS',
        'release' => {
          'major' => '7',
          'full' => '7.9.2009'
        }
      },
      'kernel' => 'Linux',
      'osfamily' => 'RedHat',
      'operatingsystem' => 'CentOS',
      'operatingsystemrelease' => '7.9.2009',
      'architecture' => 'x86_64',
      'hardwaremodel' => 'x86_64'
    },
    'ubuntu-20.04-x86_64' => {
      'os' => {
        'family' => 'Debian',
        'name' => 'Ubuntu',
        'release' => {
          'major' => '20',
          'full' => '20.04'
        }
      },
      'kernel' => 'Linux',
      'osfamily' => 'Debian',
      'operatingsystem' => 'Ubuntu',
      'operatingsystemrelease' => '20.04',
      'architecture' => 'x86_64',
      'hardwaremodel' => 'x86_64'
    },
    'darwin-21-x86_64' => {
      'os' => {
        'family' => 'Darwin',
        'name' => 'Darwin',
        'release' => {
          'major' => '21',
          'full' => '21.6.0'
        }
      },
      'kernel' => 'Darwin',
      'osfamily' => 'Darwin',
      'operatingsystem' => 'Darwin',
      'operatingsystemrelease' => '21.6.0',
      'architecture' => 'x86_64',
      'hardwaremodel' => 'x86_64'
    },
    'windows-2019-x86_64' => {
      'os' => {
        'family' => 'windows',
        'name' => 'windows',
        'release' => {
          'major' => '10',
          'full' => '10.0.17763'
        }
      },
      'kernel' => 'windows',
      'osfamily' => 'windows',
      'operatingsystem' => 'windows',
      'operatingsystemrelease' => '2019',
      'architecture' => 'x64',
      'hardwaremodel' => 'x64'
    }
  }.freeze
end
