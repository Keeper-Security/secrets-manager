require 'spec_helper'

describe 'keeper_secrets_manager_puppet::install_ksm' do
  supported_os = on_supported_os.select do |os, _facts|
    os_name = os.split('-').first
    ['redhat', 'centos', 'ubuntu', 'debian', 'darwin', 'windows'].include?(os_name)
  end

  supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:os_family) { os_facts.dig('os', 'family') || os_facts['osfamily'] || '' }
      let(:is_windows) { os_facts.dig('os', 'family') == 'windows' || os_facts['osfamily'] == 'windows' || os.start_with?('windows') }
      # Use Unix-style paths for tests since Puppet doesn't recognize Windows paths as fully qualified in test environment
      let(:config_dir) { is_windows ? 'C:/ProgramData/keeper_secret_manager' : '/opt/keeper_secret_manager' }
      let(:script_name) { is_windows ? 'install_ksm.ps1' : 'install_ksm.sh' }
      let(:script_path) { File.join(config_dir, script_name) }

      context 'with valid configuration' do
        let(:facts) do
          os_facts.merge({ 'keeper_config_dir_path' => config_dir })
        end

        it { is_expected.to compile.with_all_deps }

        it 'creates the install script file with correct permissions' do
          if is_windows
            is_expected.to contain_file(script_path)
              .with_ensure('file')
              .with_source("puppet:///modules/keeper_secrets_manager_puppet/#{script_name}")
              .without_owner
              .without_group
              .without_mode
          else
            is_expected.to contain_file(script_path)
              .with_ensure('file')
              .with_source("puppet:///modules/keeper_secrets_manager_puppet/#{script_name}")
              .with_owner('root')
              .with_group('root')
              .with_mode('0755')
          end
        end

        it 'executes the install script with correct command and path' do
          if is_windows
            is_expected.to contain_exec('install_ksm_core')
              .with_command("powershell.exe -File \"#{script_path}\"")
              .with_path(['C:/Windows/System32/WindowsPowerShell/v1.0'])
              .with_logoutput('on_failure')
              .that_requires("File[#{script_path}]")
          else
            is_expected.to contain_exec('install_ksm_core')
              .with_command("\"/bin/bash\" \"#{script_path}\"")
              .with_path(['/usr/bin', '/bin', '/usr/sbin', '/sbin'])
              .with_logoutput('on_failure')
              .that_requires("File[#{script_path}]")
          end
        end

        it 'uses the correct script name based on OS family' do
          if is_windows
            is_expected.to contain_file(script_path)
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/install_ksm.ps1')
          else
            is_expected.to contain_file(script_path)
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/install_ksm.sh')
          end
        end
      end

      context 'with valid configuration and custom config directory' do
        let(:custom_config_dir) { is_windows ? 'C:/custom/path/keeper' : '/custom/path/keeper' }
        let(:facts) do
          os_facts.merge({ 'keeper_config_dir_path' => custom_config_dir })
        end

        it { is_expected.to compile.with_all_deps }

        it 'creates the install script in the custom directory' do
          custom_script_path = File.join(custom_config_dir, script_name)
          is_expected.to contain_file(custom_script_path)
            .with_ensure('file')
            .with_source("puppet:///modules/keeper_secrets_manager_puppet/#{script_name}")
        end

        it 'executes the install script from the custom directory' do
          custom_script_path = File.join(custom_config_dir, script_name)
          if is_windows
            is_expected.to contain_exec('install_ksm_core')
              .with_command("powershell.exe -File \"#{custom_script_path}\"")
          else
            is_expected.to contain_exec('install_ksm_core')
              .with_command("\"/bin/bash\" \"#{custom_script_path}\"")
          end
        end
      end

      context 'with invalid configuration' do
        context 'when keeper_config_dir_path is undefined' do
          let(:facts) do
            os_facts.merge({ 'keeper_config_dir_path' => nil })
          end

          it 'fails with configuration error' do
            expect {
              catalogue
            }.to raise_error(%r{Configuration Error})
          end
        end

        context 'when keeper_config_dir_path fact is missing' do
          let(:facts) do
            # Remove keeper_config_dir_path from facts
            os_facts.reject { |key, _| key == 'keeper_config_dir_path' }
          end

          it 'fails with configuration error' do
            expect {
              catalogue
            }.to raise_error(%r{Configuration Error})
          end
        end
      end

      context 'with edge cases' do
        context 'when config directory has special characters' do
          let(:special_config_dir) { is_windows ? 'C:/opt/keeper secret manager' : '/opt/keeper secret manager' }
          let(:facts) do
            os_facts.merge({ 'keeper_config_dir_path' => special_config_dir })
          end

          it { is_expected.to compile.with_all_deps }

          it 'handles spaces in config directory path' do
            special_script_path = File.join(special_config_dir, script_name)
            is_expected.to contain_file(special_script_path)
              .with_ensure('file')
              .with_source("puppet:///modules/keeper_secrets_manager_puppet/#{script_name}")
          end
        end

        context 'when config directory is deeply nested' do
          let(:nested_config_dir) { is_windows ? 'C:/opt/very/deeply/nested/keeper/config' : '/opt/very/deeply/nested/keeper/config' }
          let(:facts) do
            os_facts.merge({ 'keeper_config_dir_path' => nested_config_dir })
          end

          it { is_expected.to compile.with_all_deps }

          it 'handles deeply nested config directory' do
            nested_script_path = File.join(nested_config_dir, script_name)
            is_expected.to contain_file(nested_script_path)
              .with_ensure('file')
              .with_source("puppet:///modules/keeper_secrets_manager_puppet/#{script_name}")
          end
        end
      end

      context 'with different OS family configurations' do
        context 'when OS family is explicitly set to windows' do
          let(:facts) do
            os_facts.merge({
                             'keeper_config_dir_path' => config_dir,
              'os' => { 'family' => 'windows' }
                           })
          end

          it 'uses PowerShell script and command' do
            windows_script_path = File.join(config_dir, 'install_ksm.ps1')
            is_expected.to contain_file(windows_script_path)
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/install_ksm.ps1')
              .without_owner
              .without_group
              .without_mode

            is_expected.to contain_exec('install_ksm_core')
              .with_command("powershell.exe -File \"#{windows_script_path}\"")
              .with_path(['C:/Windows/System32/WindowsPowerShell/v1.0'])
          end
        end

        context 'when OS family is explicitly set to RedHat' do
          let(:facts) do
            os_facts.merge({
                             'keeper_config_dir_path' => config_dir,
              'os' => { 'family' => 'RedHat' }
                           })
          end

          it 'uses bash script and command' do
            bash_script_path = File.join(config_dir, 'install_ksm.sh')
            is_expected.to contain_file(bash_script_path)
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/install_ksm.sh')
              .with_owner('root')
              .with_group('root')
              .with_mode('0755')

            is_expected.to contain_exec('install_ksm_core')
              .with_command("\"/bin/bash\" \"#{bash_script_path}\"")
              .with_path(['/usr/bin', '/bin', '/usr/sbin', '/sbin'])
          end
        end

        context 'when OS family is explicitly set to Debian' do
          let(:facts) do
            os_facts.merge({
                             'keeper_config_dir_path' => config_dir,
              'os' => { 'family' => 'Debian' }
                           })
          end

          it 'uses bash script and command' do
            bash_script_path = File.join(config_dir, 'install_ksm.sh')
            is_expected.to contain_file(bash_script_path)
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/install_ksm.sh')
              .with_owner('root')
              .with_group('root')
              .with_mode('0755')

            is_expected.to contain_exec('install_ksm_core')
              .with_command("\"/bin/bash\" \"#{bash_script_path}\"")
              .with_path(['/usr/bin', '/bin', '/usr/sbin', '/sbin'])
          end
        end

        context 'when OS family is explicitly set to Darwin' do
          let(:facts) do
            os_facts.merge({
                             'keeper_config_dir_path' => config_dir,
              'os' => { 'family' => 'Darwin' }
                           })
          end

          it 'uses bash script and command' do
            bash_script_path = File.join(config_dir, 'install_ksm.sh')
            is_expected.to contain_file(bash_script_path)
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/install_ksm.sh')
              .with_owner('root')
              .with_group('root')
              .with_mode('0755')

            is_expected.to contain_exec('install_ksm_core')
              .with_command("\"/bin/bash\" \"#{bash_script_path}\"")
              .with_path(['/usr/bin', '/bin', '/usr/sbin', '/sbin'])
          end
        end
      end
    end
  end
end
