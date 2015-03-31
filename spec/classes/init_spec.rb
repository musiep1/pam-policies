require 'spec_helper'
describe 'pam_policies' do

  context 'with defaults for all parameters' do
    it { should contain_class('pam_policies') }
  end
end
