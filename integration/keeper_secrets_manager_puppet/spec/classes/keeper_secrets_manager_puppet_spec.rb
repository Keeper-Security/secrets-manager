require 'spec_helper'

describe 'keeper_secrets_manager_puppet' do
  # Filter to only test Linux, macOS, and Windows
  supported_os = on_supported_os.select do |os, _os_facts|
    # Simple filtering based on operating system names
    os_name = os.split('-').first

    # Simple filtering based on operating system names
    case os_name
    when 'redhat', 'centos', 'ubuntu', 'debian'
      true
    when 'darwin'
      true
    when 'windows'
      true
    else
      false
    end
  end

  supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:os_family) { os_facts.dig('os', 'family') || os_facts['osfamily'] || '' }
      let(:facts) do
        os_facts.merge({
                         'preprocess_deferred_correct' => true,
          'keeper_config_dir_path' => config_dir
                       })
      end
      let(:is_windows) { os_facts.dig('os', 'family') == 'windows' || os_facts['osfamily'] == 'windows' || os.start_with?('windows') }
      let(:config_dir) { is_windows ? 'C:/ProgramData/keeper_secret_manager' : '/opt/keeper_secret_manager' }

      # Default pre_condition for basic tests
      let(:pre_condition) do
        <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['token', 'default_token']
                }
              }
              default: { $default }
            }
          }
          function file($path) { '{"test": "json", "config": "data"}' }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            undef
          }
          PUPPET
      end

      context 'with default (json) authentication' do
        let(:pre_condition) do
          <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['json', '/path/to/config.json']
                }
              }
              default: { $default }
            }
          }
          function file($path) { '{"test": "json", "config": "data"}' }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            undef
          }
          PUPPET
        end

        let(:facts) do
          os_facts.merge({
                           'preprocess_deferred_correct' => true,
            'keeper_config_dir_path' => config_dir
                         })
        end

        it 'creates keeper_config.json for json auth' do
          config_file = File.join(config_dir, 'keeper_config.json')
          is_expected.to contain_file(config_file).with_ensure('file')
        end
      end

      context 'with ENV authentication' do
        let(:pre_condition) do
          <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['token', 'ENV:MY_ENV_VAR']
                }
              }
              default: { $default }
            }
          }
          function file($path) { '{"test": "json", "config": "data"}' }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            if $env_var_name == 'ENV:MY_ENV_VAR' {
              'env_value'
            } else {
              undef
            }
          }
          PUPPET
        end

        let(:facts) do
          os_facts.merge({
                           'preprocess_deferred_correct' => true,
            'keeper_config_dir_path' => config_dir
                         })
        end

        it 'creates the correct resource for ENV auth' do
          if is_windows
            is_expected.to contain_exec('set_keeper_auth_value_windows')
          else
            env_file = File.join(config_dir, 'keeper_env.sh')
            is_expected.to contain_file(env_file).with_ensure('file')
          end
        end
      end

      it { is_expected.to compile.with_all_deps }

      it { is_expected.to contain_class('keeper_secrets_manager_puppet::config') }
      it { is_expected.to contain_class('keeper_secrets_manager_puppet::install_ksm') }

      it 'has proper ordering' do
        is_expected.to contain_class('keeper_secrets_manager_puppet::config')
          .that_comes_before('Class[keeper_secrets_manager_puppet::install_ksm]')
      end

      it 'contains the main class' do
        is_expected.to contain_class('keeper_secrets_manager_puppet')
      end

      it 'has no parameters' do
        is_expected.to contain_class('keeper_secrets_manager_puppet').with({})
      end

      # Test that the actual resources are created
      it 'creates the config directory' do
        is_expected.to contain_file(config_dir)
          .with_ensure('directory')
      end

      it 'creates the input.json config file' do
        config_file = File.join(config_dir, 'input.json')
        is_expected.to contain_file(config_file)
          .with_ensure('file')
      end

      it 'creates the ksm.py script file' do
        script_file = File.join(config_dir, 'ksm.py')
        is_expected.to contain_file(script_file)
          .with_ensure('file')
      end

      it 'creates the install script file' do
        install_script = File.join(config_dir, is_windows ? 'install_ksm.ps1' : 'install_ksm.sh')
        is_expected.to contain_file(install_script)
          .with_ensure('file')
      end

      it 'executes the install script' do
        is_expected.to contain_exec('install_ksm_core')
          .with_logoutput('on_failure')
      end
    end
  end
end
