describe ManageIQ::Providers::Hawkular::MiddlewareManager do
  it ".ems_type" do
    expect(described_class.ems_type).to eq('hawkular')
  end

  it ".description" do
    expect(described_class.description).to eq('Hawkular')
  end

  describe "miq_id_prefix" do
    let(:random_id) { SecureRandom.hex(10) }
    let!(:my_region) do
      MiqRegion.my_region || FactoryGirl.create(:miq_region, :region => MiqRegion.my_region_number)
    end
    let(:random_region) do
      region = Random.rand(1..99) while !region || region == my_region.region
      MiqRegion.find_by(:region => region) || FactoryGirl.create(:miq_region, :region => region)
    end

    it "must return non-empty string" do
      rval = subject.miq_id_prefix
      expect(rval.to_s.strip).not_to be_empty
    end

    it "must prefix the provided string/identifier" do
      rval = subject.miq_id_prefix(random_id)

      expect(rval).to end_with(random_id)
      expect(rval).not_to eq(random_id)
    end

    it "must generate different prefixes for different providers" do
      ems_a = FactoryGirl.create(:ems_hawkular)
      ems_b = FactoryGirl.create(:ems_hawkular)

      expect(ems_a.miq_id_prefix).not_to eq(ems_b.miq_id_prefix)
    end

    it "must generate different prefixes for same provider on different MiQ region" do
      ems_a = FactoryGirl.create(:ems_hawkular)
      ems_b = ems_a.dup
      ems_b.id = described_class.id_in_region(ems_a.id % described_class::DEFAULT_RAILS_SEQUENCE_FACTOR, random_region.region)

      expect(ems_a.miq_id_prefix).not_to eq(ems_b.miq_id_prefix)
    end
  end

  describe 'middleware operations:' do
    subject(:ems) { FactoryGirl.create(:ems_hawkular) }
    let(:mw_server) do
      FactoryGirl.create(
        :hawkular_middleware_server,
        :ext_management_system => ems,
        :ems_ref               => '/f;f1/r;server'
      )
    end
    let(:mw_domain_server) do
      FactoryGirl.create(
        :hawkular_middleware_server,
        :ext_management_system => ems,
        :ems_ref               => '/t;hawkular/f;master.Unnamed%20Domain/r;Local~~/r;Local~%2Fhost%3Dmaster/r;Local~%2Fhost%3Dmaster%2Fserver%3Dserver-one'
      )
    end
    let(:mw_domain) do
      FactoryGirl.create(
        :hawkular_middleware_domain,
        :ext_management_system => ems,
        :ems_ref               => '/t;hawkular/f;master.Unnamed%20Domain/r;Local~~/r;Local~%2Fhost%3Dmaster'
      )
    end
    let(:mw_datasource) do
      FactoryGirl.create(
        :hawkular_middleware_datasource,
        :ext_management_system => ems,
        :server_id             => mw_server.id,
        :ems_ref               => '/t;hawkular/f;master.Unnamed%20Domain/r;Local~~/r;Local~%2fsubsystem%3ddatasources%2fdata-source%3dExampleDS'
      )
    end

    before(:all) do
      MiqServer.seed
      NotificationType.seed
    end

    def notification_expectations(mw_server, op_name, type_name)
      notification = Notification.last
      expect(notification.notification_type.name).to eq(type_name)
      expect(notification.options[:op_name]).to eq(op_name)
      expect(notification.options[:mw_server]).to eq("#{mw_server.name} (#{mw_server.feed})")
    end

    def timeline_server_expectations(mw_item, op_name, status)
      event = EmsEvent.last
      expect(event.ems_id).to eq(ems.id)
      expect(event.event_type).to eq("MwServer.#{op_name}.#{status}")
      expect(event.middleware_server_id).to eq(mw_item.id)
      expect(event.middleware_server_name).to eq(mw_item.name)
    end

    def timeline_domain_expectations(status)
      event = EmsEvent.last
      expect(event.ems_id).to eq(ems.id)
      expect(event.event_type).to eq("MwDomain.Stop.#{status}")
      expect(event.middleware_domain_id).to eq(mw_domain.id)
      expect(event.middleware_domain_name).to eq(mw_domain.name)
    end

    %w(shutdown suspend resume reload restart stop).each do |operation|
      describe operation do
        it "should create a user notification and timeline event on success" do
          allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_generic_operation) do |_, &callback|
            callback.perform(:success, nil)
          end

          ems.public_send("#{operation}_middleware_server", mw_server.ems_ref)
          queue = MiqQueue.last
          expect(queue).not_to be_nil
          queue.deliver

          op_name = operation.capitalize
          notification_expectations(mw_server, op_name.to_sym, 'mw_op_success')
          timeline_server_expectations(mw_server, op_name, "Success")
        end

        it "should create a user notification and timeline event on failure" do
          allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_generic_operation) do |_, &callback|
            callback.perform(:failure, 'Error')
          end

          ems.public_send("#{operation}_middleware_server", mw_server.ems_ref)
          queue = MiqQueue.last
          expect(queue).not_to be_nil
          queue.deliver

          op_name = operation.capitalize
          notification_expectations(mw_server, op_name.to_sym, 'mw_op_failure')
          timeline_server_expectations(mw_server, op_name, "Failed")
        end
      end
    end

    %w(start restart stop kill).each do |operation|
      describe "domain server specific '#{operation}' operation:" do
        it "should create a user notification and timeline event on success" do
          allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_generic_operation) do |_, &callback|
            callback.perform(:success, nil)
          end

          ems.public_send("#{operation}_middleware_domain_server",
                          mw_domain_server.ems_ref.sub(/%2Fserver%3D/, '%2Fserver-config%3D'),
                          {},
                          :original_resource_path => mw_domain_server.ems_ref)
          queue = MiqQueue.last
          expect(queue).not_to be_nil
          queue.deliver

          op_name = operation.capitalize
          notification_expectations(mw_domain_server, op_name.to_sym, 'mw_op_success')
          timeline_server_expectations(mw_domain_server, op_name, "Success")
        end

        it "should create a user notification and timeline event on failure" do
          allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_generic_operation) do |_, &callback|
            callback.perform(:failure, 'Error')
          end

          ems.public_send("#{operation}_middleware_domain_server",
                          mw_domain_server.ems_ref.sub(/%2Fserver%3D/, '%2Fserver-config%3D'),
                          {},
                          :original_resource_path => mw_domain_server.ems_ref)

          queue = MiqQueue.last
          expect(queue).not_to be_nil
          queue.deliver

          op_name = operation.capitalize
          notification_expectations(mw_domain_server, op_name.to_sym, 'mw_op_failure')
          timeline_server_expectations(mw_domain_server, op_name, "Failed")
        end
      end
    end

    describe 'domain stop operation' do
      it 'should create a user notification and timeline event on success' do
        allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_generic_operation) do |_, &callback|
          callback.perform(:success, nil)
        end

        ems.stop_middleware_server(mw_domain.ems_ref)
        MiqQueue.last.deliver

        notification_expectations(mw_domain, :Stop, 'mw_op_success')
        timeline_domain_expectations('Success')
      end

      it 'should create a user notification and timeline event on failure' do
        allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_generic_operation) do |_, &callback|
          callback.perform(:failure, nil)
        end

        ems.stop_middleware_server(mw_domain.ems_ref)
        MiqQueue.last.deliver

        notification_expectations(mw_domain, :Stop, 'mw_op_failure')
        timeline_domain_expectations('Failed')
      end
    end

    describe 'remove datasource operation' do
      it "should create a user notification and timeline event on success" do
        allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_specific_operation) do |_, &callback|
          callback.perform(:success, nil)
        end
        ems.public_send("remove_middleware_datasource", mw_datasource.ems_ref)

        notification_expectations(mw_server, "Remove Datasource", 'mw_op_success')
      end

      it "should create a user notification and timeline event on failure" do
        allow_any_instance_of(::Hawkular::Operations::Client).to receive(:invoke_specific_operation) do |_, &callback|
          callback.perform(:failure, 'Error')
        end

        ems.public_send("remove_middleware_datasource", mw_datasource.ems_ref)

        notification_expectations(mw_server, "Remove Datasource", 'mw_op_failure')
      end
    end
  end

  describe 'connectivity' do
    let(:ems)      { FactoryGirl.create(:ems_hawkular) }
    let(:username) { 'abcdefghij' }
    let(:password) { '1234567890' }
    let(:host)     { 'awesomehawkular.org' }
    let(:port)     { 8080 }

    describe '#connect' do
      let(:endpoint)       { FactoryGirl.create(:endpoint) }
      let(:http_scheme)    { URI::HTTPS }
      let(:verify_ssl)     { 1 }
      let(:ssl_cert_store) { nil }
      let(:connection_options) do
        {
          :entrypoint  => http_scheme.build(:host => host, :port => port).to_s,
          :credentials => { :username => username, :password => password },
          :options     => { :tenant => 'hawkular', :verify_ssl => verify_ssl, :ssl_cert_store => ssl_cert_store }
        }
      end
      subject { ems.connect }

      before do
        allow(ems).to receive_messages(
          :hostname                => host,
          :port                    => port,
          :default_endpoint        => endpoint,
          :authentication_userid   => username,
          :authentication_password => password
        )
      end

      context 'non-ssl' do
        let(:http_scheme) { URI::HTTP }

        it { is_expected.to be_connected_to connection_options }
      end

      context 'ssl-without-validation' do
        let(:verify_ssl) { 0 }
        let(:endpoint)   { FactoryGirl.create(:endpoint, :security_protocol => 'ssl-without-validation') }

        it { is_expected.to be_connected_to connection_options }
      end

      context 'ssl' do
        let(:endpoint) { FactoryGirl.create(:endpoint, :security_protocol => 'ssl') }

        it { is_expected.to be_connected_to connection_options }
      end
    end

    context 'validation' do
      shared_examples 'validate' do
        let(:connection) { dup }
        let(:struct) { dup }
        before do
          allow(connection).to receive(:inventory).and_return(struct)
          allow(ems).to receive(:connect).and_return(connection)
        end

        context 'failed' do
          before do
            allow(struct).to receive(:list_feeds).and_raise(exception)
          end

          [
            [::Hawkular::Exception.new("Unauthorized", 401), MiqException::MiqInvalidCredentialsError, /Invalid credentials/],
            [::Hawkular::Exception.new("Host not found", 404), MiqException::MiqHostError, /Hawkular not found on host/],
            [::Hawkular::ConnectionException.new(nil), MiqException::MiqUnreachableError, /Unable to connect to*/],
            [URI::InvalidComponentError, MiqException::MiqHostError, /Host .* is invalid/],
            [StandardError, MiqException::Error, /Unable to verify credentials/]
          ].each do |raised, expectation, message|
            context message do
              let(:exception) { raised }

              it 'raises exception' do
                expect { subject }.to raise_error(expectation, message)
              end
            end
          end
        end

        context 'sucessfull' do
          before do
            allow(struct).to receive(:list_feeds).and_return([])
          end

          it { is_expected.to be_truthy }
        end
      end

      describe '#verify_credentials' do
        subject { ems.verify_credentials }
        include_examples 'validate'
      end

      describe '.raw_connect' do
        subject { described_class.raw_connect(host, port, username, password, nil, nil, true) }
        include_examples 'validate'
      end
    end
  end
end
