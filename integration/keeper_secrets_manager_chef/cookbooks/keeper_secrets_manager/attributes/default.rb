# Shared by both the ksm_install and ksm_fetch custom resources so a
# token-bind in ksm_fetch persists to the same config_dir that ksm_install
# writes from the encrypted data bag, without hardcoding the coupling in
# either resource's property defaults.
default['keeper_secrets_manager']['base_dir'] =
  if platform_family?('windows')
    'C:\ProgramData\keeper_secrets_manager'
  else
    '/opt/keeper_secrets_manager'
  end
