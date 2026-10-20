require 'spec_helper'
require 'facter'

describe 'preprocess_deferred_correct fact' do
  before :each do
    Facter.clear
  end

  let(:puppet_conf_content) { "[agent]\npreprocess_deferred = false\n" }

  context 'when preprocess_deferred is set to false in puppet.conf' do
    before :each do
      allow(Facter).to receive(:value).with(:os).and_return({ 'family' => 'RedHat' })
      allow(File).to receive(:exist?).and_return(true)
      allow(File).to receive(:readlines).and_return(puppet_conf_content.lines)
    end

    it 'returns true' do
      expect(Facter.fact(:preprocess_deferred_correct).value).to eq(true)
    end
  end

  context 'when preprocess_deferred is not set in puppet.conf' do
    before :each do
      allow(Facter).to receive(:value).with(:os).and_return({ 'family' => 'RedHat' })
      allow(File).to receive(:exist?).and_return(true)
      allow(File).to receive(:readlines).and_return(["[main]\n", "other_setting = true\n"])
    end

    it 'returns false' do
      expect(Facter.fact(:preprocess_deferred_correct).value).to eq(false)
    end
  end
end
