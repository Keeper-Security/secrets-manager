require 'spec_helper'
require 'json'
require 'base64'
require 'securerandom'

# Throttle retry with exponential backoff (KSM-876 / KSM-883). Unit specs exercise the private
# helpers; e2e specs drive get_secrets through post_query with a custom_post_function returning
# HTTP 403 {"error":"throttled"} responses and a stubbed `sleep` so retries never actually wait.
RSpec.describe KeeperSecretsManager::Core::SecretsManager do
  let(:config) do
    KeeperSecretsManager::Storage::InMemoryStorage.new(
      'hostname' => 'mock.keepersecurity.com',
      'clientId' => 'mock-client-id',
      'privateKey' => Base64.strict_encode64(SecureRandom.random_bytes(32)),
      'appKey' => Base64.strict_encode64(SecureRandom.random_bytes(32)),
      'serverPublicKeyId' => '10'
    )
  end

  subject(:sm) { described_class.new(config: config) }

  def throttle_body(retry_after = nil)
    body = { 'error' => 'throttled', 'message' => 'throttled' }
    body['retry_after'] = retry_after unless retry_after.nil?
    body.to_json
  end

  def resp(status_code, data)
    KeeperSecretsManager::Dto::KSMHttpResponse.new(status_code: status_code, data: data)
  end

  describe '#throttle_delay' do
    it 'produces the exponential sequence with zero jitter' do
      allow(sm).to receive(:rand).and_return(0)
      expect([0, 1, 2, 3, 4].map { |a| sm.send(:throttle_delay, a, 0) }).to eq([11, 22, 44, 88, 176])
    end

    it 'honors retry_after over the exponential backoff' do
      allow(sm).to receive(:rand).and_return(0)
      expect(sm.send(:throttle_delay, 3, 7)).to eq(7)
    end

    it 'ignores a non-positive retry_after' do
      allow(sm).to receive(:rand).and_return(0)
      expect(sm.send(:throttle_delay, 0, 0)).to eq(11)
      expect(sm.send(:throttle_delay, 1, -5)).to eq(22)
    end

    it 'keeps the first delay within the +/-25% jitter bounds' do
      allow(sm).to receive(:rand).and_return(-0.25)
      expect(sm.send(:throttle_delay, 0, 0)).to be_within(0.001).of(8.25)
      allow(sm).to receive(:rand).and_return(0.25)
      expect(sm.send(:throttle_delay, 0, 0)).to be_within(0.001).of(13.75)
    end
  end

  describe '#parse_throttle' do
    it 'detects throttled (with/without retry_after) and clamps negatives' do
      expect(sm.send(:parse_throttle, resp(403, '{"error":"throttled"}'))).to eq(0)
      expect(sm.send(:parse_throttle, resp(403, '{"result_code":"throttled","retry_after":5}'))).to eq(5)
      expect(sm.send(:parse_throttle, resp(403, '{"error":"throttled","retry_after":"3"}'))).to eq(3)
      expect(sm.send(:parse_throttle, resp(403, '{"error":"throttled","retry_after":-2}'))).to eq(0)
    end

    it 'returns nil for non-throttle / non-JSON / empty bodies' do
      expect(sm.send(:parse_throttle, resp(403, '{"error":"key"}'))).to be_nil
      expect(sm.send(:parse_throttle, resp(502, 'not json'))).to be_nil
      expect(sm.send(:parse_throttle, resp(403, ''))).to be_nil
    end
  end

  describe 'throttle retry (e2e via get_secrets)' do
    def build_sm(&post_fn)
      manager = described_class.new(config: config, custom_post_function: post_fn)
      allow(manager).to receive(:sleep) # no real waiting
      manager
    end

    it 'retries then succeeds' do
      calls = 0
      manager = build_sm do |_url, transmission_key, _payload, _ssl|
        calls += 1
        if calls == 1
          resp(403, throttle_body)
        else
          data = KeeperSecretsManager::Crypto.encrypt_aes_gcm('{"records":[],"folders":[]}', transmission_key.key)
          resp(200, data)
        end
      end

      expect(manager.get_secrets).to eq([])
      expect(manager).to have_received(:sleep).once
      expect(calls).to eq(2)
    end

    it 'raises ThrottledError after exhausting retries' do
      calls = 0
      manager = build_sm do |_url, _tk, _payload, _ssl|
        calls += 1
        resp(403, throttle_body)
      end

      expect { manager.get_secrets }.to raise_error(KeeperSecretsManager::ThrottledError)
      expect(manager).to have_received(:sleep).exactly(5).times
      expect(calls).to eq(6) # 5 retries + the final throttled response
    end

    it 'honors retry_after from the response body' do
      captured = []
      calls = 0
      manager = described_class.new(config: config, custom_post_function: lambda do |_url, _tk, _payload, _ssl|
        calls += 1
        calls == 1 ? resp(403, throttle_body(3)) : resp(403, throttle_body)
      end)
      allow(manager).to receive(:sleep) { |seconds| captured << seconds }

      expect { manager.get_secrets }.to raise_error(KeeperSecretsManager::ThrottledError)
      # retry_after = 3s with +/-25% jitter -> [2.25s, 3.75s]
      expect(captured.first).to be_between(2.25, 3.75)
    end

    it 'does not retry a non-throttle 403' do
      manager = build_sm { |_url, _tk, _payload, _ssl| resp(403, '{"error":"access_denied","message":"nope"}') }

      expect { manager.get_secrets }.to raise_error(KeeperSecretsManager::Error) do |e|
        expect(e).not_to be_a(KeeperSecretsManager::ThrottledError)
      end
      expect(manager).not_to have_received(:sleep)
    end

    it 'does not retry a 502 carrying a throttled body (403 gate)' do
      manager = build_sm { |_url, _tk, _payload, _ssl| resp(502, throttle_body) }

      expect { manager.get_secrets }.to raise_error(StandardError)
      expect(manager).not_to have_received(:sleep)
    end
  end
end
