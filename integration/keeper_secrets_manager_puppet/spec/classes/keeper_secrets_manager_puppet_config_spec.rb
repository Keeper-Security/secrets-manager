require 'spec_helper'

describe 'keeper_secrets_manager_puppet::config' do
  supported_os = on_supported_os.select do |os, _facts|
    os_name = os.split('-').first
    ['redhat', 'centos', 'ubuntu', 'debian', 'darwin', 'windows'].include?(os_name)
  end

  supported_os.each do |os, os_facts|
    context "on #{os}" do
      let(:os_family) { os_facts.dig('os', 'family') || os_facts['osfamily'] || '' }
      let(:is_windows) { os_facts.dig('os', 'family') == 'windows' || os_facts['osfamily'] == 'windows' || os.start_with?('windows') }
      # Use OS-specific paths for tests
      let(:config_dir) { is_windows ? 'C:/ProgramData/keeper_secret_manager' : '/opt/keeper_secret_manager' }
      let(:input_json) { File.join(config_dir, 'input.json') }
      let(:ksm_py) { File.join(config_dir, 'ksm.py') }
      let(:keeper_config) { File.join(config_dir, 'keeper_config.json') }

      context 'with valid JSON authentication configuration' do
        let(:facts) do
          os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
        end

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
          function file($path) {
            '{"test": "json", "config": "data"}'
          }
          PUPPET
        end

        it { is_expected.to compile.with_all_deps }

        it 'creates the config directory' do
          if is_windows
            is_expected.to contain_file(config_dir)
              .with_ensure('directory')
              .without_owner
              .without_group
              .without_mode
          else
            is_expected.to contain_file(config_dir)
              .with_ensure('directory')
              .with_owner('root')
              .with_group('root')
              .with_mode('0755')
          end
        end

        it 'creates the input.json config file with correct permissions' do
          if is_windows
            is_expected.to contain_file(input_json)
              .with_ensure('file')
              .without_owner
              .without_group
              .without_mode
              .that_requires("File[#{config_dir}]")
          else
            is_expected.to contain_file(input_json)
              .with_ensure('file')
              .with_owner('root')
              .with_group('root')
              .with_mode('0644')
              .that_requires("File[#{config_dir}]")
          end
        end

        it 'creates the ksm.py script' do
          if is_windows
            is_expected.to contain_file(ksm_py)
              .with_ensure('file')
              .without_owner
              .without_group
              .without_mode
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/ksm.py')
              .that_requires("File[#{config_dir}]")
          else
            is_expected.to contain_file(ksm_py)
              .with_ensure('file')
              .with_owner('root')
              .with_group('root')
              .with_mode('0755')
              .with_source('puppet:///modules/keeper_secrets_manager_puppet/ksm.py')
              .that_requires("File[#{config_dir}]")
          end
        end

        it 'creates keeper_config.json for JSON authentication' do
          if is_windows
            is_expected.to contain_file(keeper_config)
              .with_ensure('file')
              .without_owner
              .without_group
              .without_mode
              .with_content('{"test": "json", "config": "data"}')
              .that_requires("File[#{config_dir}]")
          else
            is_expected.to contain_file(keeper_config)
              .with_ensure('file')
              .with_owner('root')
              .with_group('root')
              .with_mode('0600')
              .with_content('{"test": "json", "config": "data"}')
              .that_requires("File[#{config_dir}]")
          end
        end
      end

      context 'with valid base64 authentication configuration' do
        let(:facts) do
          os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
        end

        let(:pre_condition) do
          <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['base64', 'base64_encoded_value']
                }
              }
              default: { $default }
            }
          }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            undef
          }
          PUPPET
        end

        it { is_expected.to compile.with_all_deps }

        it 'creates the config directory and files without keeper_config.json' do
          is_expected.to contain_file(config_dir)
          is_expected.to contain_file(input_json)
          is_expected.to contain_file(ksm_py)
          is_expected.not_to contain_file(keeper_config)
        end
      end

      context 'with token authentication configuration' do
        let(:facts) do
          os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
        end

        let(:pre_condition) do
          <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['token', 'ENV:KEEPER_TOKEN']
                }
              }
              default: { $default }
            }
          }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            '/path/to/token/config.json'
          }
          PUPPET
        end

        it { is_expected.to compile.with_all_deps }

        it 'handles token authentication with environment variable' do
          env_file = File.join(config_dir, 'keeper_env.sh')
          if is_windows
            # Windows uses registry instead of env file
            is_expected.not_to contain_file(env_file)
            is_expected.to contain_exec('set_keeper_auth_value_windows')
              .with_command("powershell -Command \"[Environment]::SetEnvironmentVariable('KEEPER_CONFIG', '/path/to/token/config.json', 'Machine')\"")
              .with_path(['C:/Windows/System32/WindowsPowerShell/v1.0'])
          else
            is_expected.to contain_file(env_file)
              .with_ensure('file')
              .with_owner('root')
              .with_group('root')
              .with_mode('0600')
              .with_content("export KEEPER_CONFIG='/path/to/token/config.json'\n")
          end
        end
      end

      context 'with token authentication but no environment variable' do
        let(:facts) do
          os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
        end

        let(:pre_condition) do
          <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['token', 'ENV:KEEPER_TOKEN']
                }
              }
              default: { $default }
            }
          }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            undef
          }
          PUPPET
        end

        it 'fails with environment variable error' do
          expect {
            catalogue
          }.to raise_error(%r{Environment Variable Error})
        end
      end

      context 'with token authentication using non-ENV value' do
        let(:facts) do
          os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
        end

        let(:pre_condition) do
          <<-PUPPET
          function lookup($key, $default = undef, $merge = undef) {
            case $key {
              'keeper::config': {
                {
                  'authentication' => ['token', 'direct_token_value']
                }
              }
              default: { $default }
            }
          }
          function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
            undef
          }
          PUPPET
        end

        it { is_expected.to compile.with_all_deps }

        it 'creates basic files without environment setup' do
          is_expected.to contain_file(config_dir)
          is_expected.to contain_file(input_json)
          is_expected.to contain_file(ksm_py)
          is_expected.not_to contain_file(File.join(config_dir, 'keeper_env.sh'))
          is_expected.not_to contain_exec('set_keeper_auth_value_windows')
        end
      end

      context 'with invalid configurations' do
        context 'when preprocess_deferred_correct is false' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => false, 'keeper_config_dir_path' => config_dir })
          end

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
            PUPPET
          end

          it 'fails with puppet configuration error' do
            expect {
              catalogue
            }.to raise_error(%r{Puppet Configuration Error})
          end
        end

        context 'when keeper::config is missing' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              undef
            }
            PUPPET
          end

          it 'fails with undefined value error' do
            expect {
              catalogue
            }.to raise_error(%r{Operator '\[\]' is not applicable to an Undef Value})
          end
        end

        context 'when authentication is not an array' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => 'not_an_array'
                  }
                }
                default: { $default }
              }
            }
            PUPPET
          end

          it 'fails with configuration error' do
            expect {
              catalogue
            }.to raise_error(%r{Configuration Error})
          end
        end

        context 'when authentication array is empty' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => []
                  }
                }
                default: { $default }
              }
            }
            PUPPET
          end

          it 'fails with configuration error' do
            expect {
              catalogue
            }.to raise_error(%r{Configuration Error})
          end
        end

        context 'when authentication method is unsupported' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['unsupported_method', 'value']
                  }
                }
                default: { $default }
              }
            }
            PUPPET
          end

          it 'fails with authentication error' do
            expect {
              catalogue
            }.to raise_error(%r{Authentication Error})
          end
        end

        context 'when authentication value is missing' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['json']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              undef
            }
            PUPPET
          end

          it 'fails with authentication value error' do
            expect {
              catalogue
            }.to raise_error(%r{Authentication Value Error})
          end
        end

        context 'when authentication value is empty string' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['json', '']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              undef
            }
            PUPPET
          end

          it 'fails with authentication value error' do
            expect {
              catalogue
            }.to raise_error(%r{Authentication Value Error})
          end
        end

        context 'when JSON file contains invalid JSON' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

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
            function file($path) {
              'invalid json content'
            }
            PUPPET
          end

          it 'fails with JSON parsing error' do
            expect {
              catalogue
            }.to raise_error(%r{Error while evaluating a Function Call})
          end
        end

        context 'when JSON file does not exist' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['json', '/nonexistent/file.json']
                  }
                }
                default: { $default }
              }
            }
            function file($path) {
              fail('File not found')
            }
            PUPPET
          end

          it 'fails with file not found error' do
            expect {
              catalogue
            }.to raise_error(%r{File not found})
          end
        end

        context 'when environment variable has quotes' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['token', 'ENV:KEEPER_TOKEN']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              '"quoted_value"'
            }
            PUPPET
          end

          it 'strips quotes from environment variable value' do
            env_file = File.join(config_dir, 'keeper_env.sh')
            if is_windows
              is_expected.to contain_exec('set_keeper_auth_value_windows')
                .with_command("powershell -Command \"[Environment]::SetEnvironmentVariable('KEEPER_CONFIG', 'quoted_value', 'Machine')\"")
            else
              is_expected.to contain_file(env_file)
                .with_content("export KEEPER_CONFIG='quoted_value'\n")
            end
          end
        end

        context 'when JSON authentication uses environment variable with quotes' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['json', 'ENV:KEEPER_CONFIG_PATH']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              '"/path/to/quoted/config.json"'
            }
            function file($path) {
              '{"test": "json", "config": "data"}'
            }
            PUPPET
          end

          it 'strips quotes from environment variable value for JSON authentication' do
            if is_windows
              is_expected.to contain_file(keeper_config)
                .with_ensure('file')
                .without_owner
                .without_group
                .without_mode
                .with_content('{"test": "json", "config": "data"}')
                .that_requires("File[#{config_dir}]")
            else
              is_expected.to contain_file(keeper_config)
                .with_ensure('file')
                .with_owner('root')
                .with_group('root')
                .with_mode('0600')
                .with_content('{"test": "json", "config": "data"}')
                .that_requires("File[#{config_dir}]")
            end
          end
        end

        context 'when environment variable has single quotes' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['token', 'ENV:KEEPER_TOKEN']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              "'single_quoted_value'"
            }
            PUPPET
          end

          it 'strips single quotes from environment variable value' do
            env_file = File.join(config_dir, 'keeper_env.sh')
            if is_windows
              is_expected.to contain_exec('set_keeper_auth_value_windows')
                .with_command("powershell -Command \"[Environment]::SetEnvironmentVariable('KEEPER_CONFIG', 'single_quoted_value', 'Machine')\"")
            else
              is_expected.to contain_file(env_file)
                .with_content("export KEEPER_CONFIG='single_quoted_value'\n")
            end
          end
        end

        context 'when environment variable has no quotes' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['token', 'ENV:KEEPER_TOKEN']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              'unquoted_value'
            }
            PUPPET
          end

          it 'preserves unquoted environment variable value' do
            env_file = File.join(config_dir, 'keeper_env.sh')
            if is_windows
              is_expected.to contain_exec('set_keeper_auth_value_windows')
                .with_command("powershell -Command \"[Environment]::SetEnvironmentVariable('KEEPER_CONFIG', 'unquoted_value', 'Machine')\"")
            else
              is_expected.to contain_file(env_file)
                .with_content("export KEEPER_CONFIG='unquoted_value'\n")
            end
          end
        end

        context 'when environment variable is specified but not set' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['token', 'ENV:MISSING_VAR']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              undef
            }
            PUPPET
          end

          it 'fails with environment variable error' do
            expect {
              catalogue
            }.to raise_error(%r{Environment Variable Error.*ENV:MISSING_VAR})
          end
        end

        context 'when JSON authentication uses environment variable that is not set' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['json', 'ENV:MISSING_CONFIG_PATH']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              undef
            }
            PUPPET
          end

          it 'fails with environment variable error' do
            expect {
              catalogue
            }.to raise_error(%r{Environment Variable Error.*ENV:MISSING_CONFIG_PATH})
          end
        end

        context 'when base64 authentication uses environment variable that is not set' do
          let(:facts) do
            os_facts.merge({ 'preprocess_deferred_correct' => true, 'keeper_config_dir_path' => config_dir })
          end

          let(:pre_condition) do
            <<-PUPPET
            function lookup($key, $default = undef, $merge = undef) {
              case $key {
                'keeper::config': {
                  {
                    'authentication' => ['base64', 'ENV:MISSING_BASE64_VAR']
                  }
                }
                default: { $default }
              }
            }
            function keeper_secrets_manager_puppet::lookup_env_value($env_var_name) {
              undef
            }
            PUPPET
          end

          it 'fails with environment variable error' do
            expect {
              catalogue
            }.to raise_error(%r{Environment Variable Error.*ENV:MISSING_BASE64_VAR})
          end
        end
      end
    end
  end
end
