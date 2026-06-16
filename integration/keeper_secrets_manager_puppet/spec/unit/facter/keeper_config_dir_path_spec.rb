require 'spec_helper'
require 'facter'

describe 'keeper_config_dir_path fact' do
  before :each do
    Facter.clear
  end

  context 'on Linux' do
    before :each do
      allow(Facter).to receive(:value).with(:os).and_return({ 'family' => 'RedHat' })
    end

    it 'returns the UNIX config path' do
      expect(Facter.fact(:keeper_config_dir_path).value).to eq('/opt/keeper_secret_manager')
    end
  end

  context 'on Windows' do
    before :each do
      allow(Facter).to receive(:value).with(:os).and_return({ 'family' => 'windows' })
    end

    it 'returns the Windows config path' do
      expect(Facter.fact(:keeper_config_dir_path).value).to eq('C:/ProgramData/keeper_secret_manager')
    end
  end
end
