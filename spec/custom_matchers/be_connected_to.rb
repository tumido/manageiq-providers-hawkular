RSpec::Matchers.define :be_connected_to do |connection|
  match do |client|
    expect(client.state).to eq connection
  end
end
