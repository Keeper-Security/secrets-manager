# keeper_secrets_manager CHANGELOG

This file is used to list changes made in each version of the keeper_secrets_manager cookbook.

## 1.0.0

Initial release. Not yet published - this cookbook talks to the Keeper vault
through the native `keeper_secrets_manager` Ruby SDK gem, not Python.

- Added `ksm_install` custom resource, which installs a pinned version of the
  `keeper_secrets_manager` gem via `chef_gem` and writes the encrypted-data-bag
  config file
- Added `ksm_fetch` custom resource, which reads `input.json` and resolves
  each secret directly against the Ruby SDK
- Three authentication methods: `base64` (encrypted data bag or
  `KEEPER_CONFIG` env var), `token` (one-time token, persisted after binding),
  `json` (a literal config file path)
- Three secret output modes: `env:` (sets a real process `ENV` variable),
  `file:` (written to disk, `chmod 0600`), and direct/no-prefix (stored in
  `node.run_state['keeper_secrets']`, never written to disk)
- Cross-platform support (Linux, macOS, Windows)
- Requires Chef Infra Client >= 18.0 (the Ruby SDK requires Ruby >= 3.1,
  which Chef 18 is the first line to ship on all supported platforms)
- Test suite: RSpec for the shared notation-parsing library, ChefSpec for
  both custom resources and recipes, InSpec for the Test Kitchen suite

### Breaking changes from earlier drafts of this cookbook

- Minimum Chef version raised from 16.0 to 18.0
- `ksm_install`'s `python_sdk`, `cli_tool`, and `user_install` properties are
  gone - there is no Python dependency to configure
- `ksm_fetch`'s `deploy_path` and `timeout` properties are gone - there is no
  script to deploy, and the SDK has no configurable request timeout
- Direct/no-prefix secret output no longer writes `keeper_output.txt` - read
  it from `node.run_state['keeper_secrets']` in a `lazy { }` block instead
