# frozen_string_literal: true

require 'spec_helper'
require 'json'
require 'base64'
require 'openssl'

# Ports the Python reference suite sdk/python/core/tests/record_link_test.py (18 cases,
# KSM-992) to Ruby (KSM-1013). Ruby predicate accessors use a trailing `?` and drop the
# redundant `is_` prefix, so is_admin_user/is_launch_credential/is_iam_user become
# admin_user?/launch_credential?/iam_user?.
RSpec.describe KeeperSecretsManager::Dto::KeeperRecordLink do
  # --- fixture helpers (mirror the Python plain_link/encrypted_link helpers) ---

  def random_key
    KeeperSecretsManager::Crypto.generate_random_bytes(32)
  end

  # A link whose data is base64 of the given plain JSON payload.
  def plain_link(payload, path: nil, record_uid: 'RU_test')
    described_class.new(
      'recordUid' => record_uid,
      'data' => Base64.strict_encode64(JSON.generate(payload)),
      'path' => path
    )
  end

  # A link whose data is base64 of the payload encrypted with AES-256-GCM.
  def encrypted_link(payload, key, path: nil, record_uid: 'RU_test')
    ciphertext = KeeperSecretsManager::Crypto.encrypt_aes_gcm(JSON.generate(payload), key)
    described_class.new(
      'recordUid' => record_uid,
      'data' => Base64.strict_encode64(ciphertext),
      'path' => path
    )
  end

  # A link built from an arbitrary (or nil) data string.
  def raw_link(data, path: nil, record_uid: 'RU')
    described_class.new('recordUid' => record_uid, 'data' => data, 'path' => path)
  end

  # AES-256-GCM encrypt with a caller-chosen IV (iv + ciphertext + tag), matching the
  # Crypto.decrypt_aes_gcm wire format. Used to force a JSON-like leading byte.
  def encrypt_gcm_with_iv(plaintext, key, iv)
    cipher = OpenSSL::Cipher.new('AES-256-GCM')
    cipher.encrypt
    cipher.iv = iv
    cipher.key = key
    encrypted = cipher.update(plaintext) + cipher.final
    iv + encrypted + cipher.auth_tag(16)
  end

  it 'reads boolean accessors from plain JSON; absent keys default to false' do
    link = plain_link({ 'is_admin' => true, 'rotation' => true, 'connections' => false })

    expect(link.admin_user?).to be true
    expect(link.allows_rotation?).to be true
    expect(link.allows_connections?).to be false

    # Absent keys must default to false
    expect(link.allows_port_forwards?).to be false
    expect(link.launch_credential?).to be false
    expect(link.iam_user?).to be false
    expect(link.belongs_to?).to be false
    expect(link.no_update_services?).to be false
  end

  it 'reads integer version, decoded data and the readable-JSON heuristic' do
    link = plain_link({ 'version' => 3, 'is_admin' => false })
    expect(link.get_link_data_version).to eq(3)
    decoded = link.get_decoded_data
    expect(decoded).not_to be_nil
    expect(decoded).to start_with('{')
    expect(link.has_readable_data?).to be true

    # Non-JSON (but valid base64) decoded content is not "readable"
    raw = raw_link(Base64.strict_encode64('not json at all'))
    expect(raw.has_readable_data?).to be false
    expect(raw.get_link_data_version).to be_nil

    # Invalid base64 decodes to nil, never raises
    bad = raw_link('!!! not base64 !!!')
    expect(bad.get_decoded_data).to be_nil
    expect(bad.get_link_data).to be_nil
  end

  it 'gates might_be_encrypted? to the known encrypted paths only' do
    expect(plain_link({}, path: 'ai_settings').might_be_encrypted?).to be true
    expect(plain_link({}, path: 'jit_settings').might_be_encrypted?).to be true
    expect(plain_link({}, path: 'meta').might_be_encrypted?).to be false
    expect(plain_link({}, path: 'something_else').might_be_encrypted?).to be false
    expect(plain_link({}, path: nil).might_be_encrypted?).to be false
  end

  it 'round-trips AES-256-GCM decryption; wrong/absent key gives nil' do
    key = random_key
    payload = { 'enabled' => true, 'ttl' => 3600 }
    link = encrypted_link(payload, key, path: 'jit_settings')

    decrypted = link.get_decrypted_data(key)
    expect(decrypted).not_to be_nil
    expect(JSON.parse(decrypted)).to eq(payload)

    expect(link.get_decrypted_data(nil)).to be_nil
    expect(link.get_decrypted_data(random_key)).to be_nil
  end

  it 'auto-detects plain JSON vs encrypted data in get_link_data' do
    plain = plain_link({ 'aiEnabled' => true }, path: 'ai_settings')
    data = plain.get_link_data
    expect(data).not_to be_nil
    expect(data['aiEnabled']).to be true

    key = random_key
    enc = encrypted_link({ 'enabled' => true }, key, path: 'jit_settings')
    expect(enc.get_link_data).to be_nil
    data = enc.get_link_data(key)
    expect(data).not_to be_nil
    expect(data['enabled']).to be true
  end

  it 'gates settings accessors to the matching path' do
    key = random_key
    ai = plain_link({ 'aiEnabled' => true }, path: 'ai_settings')
    jit = plain_link({ 'enabled' => true }, path: 'jit_settings')

    expect(ai.get_ai_settings_data(key)).not_to be_nil
    expect(ai.get_jit_settings_data(key)).to be_nil
    expect(jit.get_jit_settings_data(key)).not_to be_nil
    expect(jit.get_ai_settings_data(key)).to be_nil

    expect(ai.get_settings_for_path('ai_settings')).not_to be_nil
    expect(ai.get_settings_for_path('other')).to be_nil
  end

  it 'builds typed links via KeeperRecord#get_links while leaving raw links unchanged' do
    links_data = [
      # meta self-link (plain JSON, live shape)
      { 'recordUid' => 'mainUid', 'path' => 'meta',
        'data' => Base64.strict_encode64(JSON.generate('allowedSettings' => { 'rotation' => true }, 'version' => 1)) },
      # credential link to another record
      { 'recordUid' => 'linkedUid', 'path' => nil,
        'data' => Base64.strict_encode64(JSON.generate('is_admin' => true, 'is_launch_credential' => true)) },
      # pure reference link (no data)
      { 'recordUid' => 'referencedUid', 'data' => nil, 'path' => nil },
      # malformed entry without recordUid is kept raw but skipped by get_links
      { 'data' => nil, 'path' => nil }
    ]
    record = KeeperSecretsManager::Dto::KeeperRecord.new(
      'recordUid' => 'r', 'data' => { 'title' => 'Main Record', 'type' => 'login' }, 'links' => links_data
    )

    # The raw links field is unchanged (back-compat)
    expect(record.links.length).to eq(4)
    expect(record.links).to eq(links_data)

    links = record.get_links
    expect(links.length).to eq(3)
    expect(links).to all(be_a(described_class))

    meta = links[0]
    expect(meta.record_uid).to eq('mainUid')
    expect(meta.path).to eq('meta')
    expect(meta.allows_rotation?).to be true
    expect(meta.get_link_data_version).to eq(1)

    cred = links[1]
    expect(cred.record_uid).to eq('linkedUid')
    expect(cred.admin_user?).to be true
    expect(cred.launch_credential?).to be true

    ref = links[2]
    expect(ref.record_uid).to eq('referencedUid')
    expect(ref.get_link_data).to be_nil
  end

  it 'does not coerce string-encoded values to bool/int' do
    link = plain_link({ 'is_admin' => 'true', 'rotation' => 'false', 'version' => '3' })
    expect(link.admin_user?).to be false
    expect(link.allows_rotation?).to be false
    expect(link.get_link_data_version).to be_nil

    # Real JSON bool/number ARE read
    typed = plain_link({ 'is_admin' => true, 'version' => 3 })
    expect(typed.admin_user?).to be true
    expect(typed.get_link_data_version).to eq(3)

    # A boolean must not count as an integer version
    bool_version = plain_link({ 'version' => true })
    expect(bool_version.get_link_data_version).to be_nil
  end

  it 'detects encrypted data by content, not by path naming' do
    key = random_key
    ciphertext = KeeperSecretsManager::Crypto.encrypt_aes_gcm('some secret bytes', key)
    enc = raw_link(Base64.strict_encode64(ciphertext))
    expect(enc.has_encrypted_data?).to be true

    text = raw_link(Base64.strict_encode64('just plain readable text, not json'))
    expect(text.has_encrypted_data?).to be false

    expect(plain_link({ 'a' => 1 }).has_encrypted_data?).to be false

    no_data = raw_link(nil)
    expect(no_data.has_encrypted_data?).to be false
  end

  it 'decrypts an encrypted payload for a matching path via get_settings_for_path' do
    key = random_key
    link = encrypted_link({ 'customSetting' => 42 }, key, path: 'custom_settings')

    data = link.get_settings_for_path('custom_settings', key)
    expect(data).not_to be_nil
    expect(data['customSetting']).to eq(42)
    expect(link.get_settings_for_path('other', key)).to be_nil
  end

  it 'reads meta self-links with the allowedSettings fallback and top-level fields' do
    link = plain_link({
                        'allowedSettings' => {
                          'rotation' => true, 'connections' => true, 'portForwards' => true,
                          'sessionRecording' => true, 'typescriptRecording' => false,
                          'aiEnabled' => true, 'aiSessionTerminate' => true, 'remoteBrowserIsolation' => true
                        },
                        'rotateOnTermination' => false, 'version' => 1, 'no_update_services' => true
                      }, path: 'meta')

    # Permission booleans read from allowedSettings when absent at the top level
    expect(link.allows_rotation?).to be true
    expect(link.allows_connections?).to be true
    expect(link.allows_port_forwards?).to be true
    expect(link.allows_session_recording?).to be true
    expect(link.allows_typescript_recording?).to be false
    expect(link.allows_remote_browser_isolation?).to be true
    expect(link.ai_enabled?).to be true
    expect(link.ai_session_terminate?).to be true

    # Top-level fields
    expect(link.rotates_on_termination?).to be false
    expect(link.get_link_data_version).to eq(1)
    expect(link.no_update_services?).to be true

    # Dict accessors
    expect(link.get_allowed_settings['rotation']).to be true
    meta = link.get_meta_data
    expect(meta).not_to be_nil
    expect(meta['version']).to eq(1)
    expect(plain_link({}, path: nil).get_meta_data).to be_nil
  end

  it 'reads credential links: user flags and the nested rotation_settings' do
    link = plain_link({
                        'is_admin' => true, 'is_iam_user' => false, 'belongs_to' => true,
                        'is_launch_credential' => true,
                        'rotation_settings' => {
                          'schedule' => '', 'pwd_complexity' => 'ZmFrZS1jb21wbGV4aXR5',
                          'disabled' => false, 'noop' => false, 'saas_record_uid_list' => []
                        }
                      })

    expect(link.admin_user?).to be true
    expect(link.iam_user?).to be false
    expect(link.belongs_to?).to be true
    expect(link.launch_credential?).to be true

    rotation_settings = link.get_rotation_settings
    expect(rotation_settings).not_to be_nil
    expect(rotation_settings['schedule']).to eq('')
    expect(rotation_settings['disabled']).to be false
    expect(rotation_settings['saas_record_uid_list']).to eq([])

    expect(plain_link({ 'is_admin' => true }).get_rotation_settings).to be_nil
  end

  it 'answers all accessors safely for a data-less reference link' do
    link = raw_link(nil, record_uid: 'RU_ref')

    expect(link.record_uid).to eq('RU_ref')
    expect(link.admin_user?).to be false
    expect(link.allows_rotation?).to be false
    expect(link.get_link_data_version).to be_nil
    expect(link.get_decoded_data).to be_nil
    expect(link.get_decrypted_data(random_key)).to be_nil
    expect(link.get_link_data).to be_nil
    expect(link.get_allowed_settings).to eq({})
    expect(link.get_rotation_settings).to be_nil
    expect(link.has_readable_data?).to be false
    expect(link.has_encrypted_data?).to be false
  end

  it 'decrypts ai_settings links to the riskLevels payload (lossless)' do
    key = random_key
    payload = {
      'version' => 'v1.0.0',
      'riskLevels' => {
        'critical' => { 'tags' => { 'allow' => [], 'deny' => [] }, 'aiSessionTerminate' => true },
        'high' => { 'tags' => { 'allow' => [], 'deny' => [] }, 'aiSessionTerminate' => true },
        'medium' => { 'tags' => { 'allow' => [], 'deny' => [] }, 'aiSessionTerminate' => true },
        'low' => { 'tags' => { 'allow' => [] }, 'aiSessionTerminate' => false }
      }
    }
    link = encrypted_link(payload, key, path: 'ai_settings')

    data = link.get_ai_settings_data(key)
    expect(data).not_to be_nil
    expect(data).to eq(payload)

    # The live version field is a string here, so the integer accessor yields nil
    expect(link.get_link_data_version).to be_nil
  end

  it 'decrypts jit_settings links to the elevation payload' do
    key = random_key
    payload = {
      'createEphemeral' => true, 'elevate' => true, 'elevationMethod' => 'group',
      'elevationString' => 'arn:aws', 'baseDistinguishedName' => ''
    }
    link = encrypted_link(payload, key, path: 'jit_settings')

    data = link.get_jit_settings_data(key)
    expect(data).not_to be_nil
    expect(data).to eq(payload)
  end

  it 'preserves unknown link keys in raw and unknown payload fields in get_link_data' do
    payload = { 'is_admin' => true, 'futureField' => { 'nested' => [1, 2, 3] } }
    link_dict = {
      'recordUid' => 'RU',
      'data' => Base64.strict_encode64(JSON.generate(payload)),
      'path' => nil,
      'futureLinkKey' => 'kept'
    }
    link = described_class.new(link_dict)

    expect(link.raw).to eq(link_dict)
    expect(link.raw['futureLinkKey']).to eq('kept')

    data = link.get_link_data
    expect(data['futureField']).to eq('nested' => [1, 2, 3])
  end

  it 'lets a top-level boolean win over the allowedSettings fallback' do
    link = plain_link({ 'rotation' => false, 'allowedSettings' => { 'rotation' => true } })
    expect(link.allows_rotation?).to be false

    only_nested = plain_link({ 'allowedSettings' => { 'rotation' => true } })
    expect(only_nested.allows_rotation?).to be true
  end

  it 'falls through to decryption when ciphertext coincidentally starts with a JSON marker' do
    key = random_key
    payload = { 'createEphemeral' => true, 'elevate' => true }

    ['{', '['].each do |marker|
      iv = marker.b + KeeperSecretsManager::Crypto.generate_random_bytes(11)
      ciphertext = encrypt_gcm_with_iv(JSON.generate(payload), key, iv)
      link = raw_link(Base64.strict_encode64(ciphertext), path: 'jit_settings')

      decoded = link.get_decoded_data
      expect(decoded[0]).to eq(marker)

      expect(link.get_link_data(key)).to eq(payload)
      expect(link.get_jit_settings_data(key)).to eq(payload)
      expect(link.get_settings_for_path('jit_settings', key)).to eq(payload)
      expect(link.get_link_data(nil)).to be_nil
    end

    # The plain-JSON fast path is unaffected.
    expect(plain_link({ 'a' => 1 }).get_link_data).to eq('a' => 1)
  end

  describe 'request_links transport plumbing' do
    it 'defaults QueryOptions#request_links to nil and stores an explicit value' do
      expect(KeeperSecretsManager::Dto::QueryOptions.new.request_links).to be_nil
      expect(KeeperSecretsManager::Dto::QueryOptions.new(request_links: true).request_links).to be true
    end

    it 'serializes GetPayload#request_links to requestLinks only when set' do
      payload = KeeperSecretsManager::Dto::GetPayload.new
      expect(payload.to_h).not_to include('requestLinks')

      payload.request_links = true
      expect(payload.to_h).to include('requestLinks' => true)
    end
  end
end
