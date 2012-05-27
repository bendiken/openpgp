module OpenPGP
  class Engine
    class OpenSSL < Engine
      ##
      # @param  [Boolean] reload
      # @return [void]
      # @raise  [LoadError]
      def self.load!(reload = false)
        require 'openssl' unless defined?(::OpenSSL) || reload
      end

      ##
      # @return [void]
      # @raise  [LoadError]
      def self.install!
        load!
        [Random, Digest].each { |mod| install_extensions! mod }
      end

      ##
      # Wrap OpenSSL RSA methods for use with OpenPGP
      class RSA
        def initialize(packet)
          packet = OpenPGP::Message::parse(packet) if packet.is_a?(String)
          @key = @message = nil
          if packet.is_a?(OpenPGP::Packet::PublicKey) || \
            (packet.respond_to?(:first) && packet.first.is_a?(OpenPGP::Packet::PublicKey))
            @key = packet
          else
            @message = packet
          end
        end

        ##
        # @param  [String] keyid (Optional)
        # @return OpenPGP::Packet::PublicKey
        def key(keyid=nil)
          return nil unless @key
          keyid.upcase! if keyid
          if @key.is_a?(Enumerable) # Like an OpenPGP::Message
            @key.select {|p| p.is_a?(OpenPGP::Packet::PublicKey) && (!keyid || \
              p.fingerprint[keyid.length*-1,keyid.length].upcase == keyid)
            }.first
          end || @key
        end

        ##
        # @param  [String] keyid (Optional)
        # @return OpenSSL::PKey::RSA
        def rsa_key(keyid=nil)
          self.class.convert_key(key(keyid))
        end

        ##
        # @param  packet message to verify with @key, or key (OpenPGP or RSA) to check @message with
        # @param  [Integer] index specify which signature to verify (if there is more than one)
        # @return Boolean
        def verify(packet, index=0)
          packet = OpenPGP::Message::parse(packet) if packet.is_a?(String)
          if packet.is_a?(OpenPGP::Message) && !packet.first.is_a?(OpenPGP::Packet::PublicKey)
            m = packet
            k = self
          else
            m = @message
            k = self.class.new(packet)
          end

          return nil unless m
          signature_packet, data_packet = m.signature_and_data(index)
          k = k.rsa_key(signature_packet.issuer)
          return nil unless k && signature_packet.key_algorithm_name == 'RSA'

          return m.verify({'RSA' => {signature_packet.hash_algorithm_name => lambda {|m,s|
            k.verify(signature_packet.hash_algorithm_name, s.first, m)
          }}})
        end

        ##
        # @param  packet message to sign with @key or key (OpenPGP or RSA) to sign @message with
        # @param  [String] hash name of hash function to use (default SHA256)
        # @param  [String] keyid id of key to use (if there is more than one)
        # @return OpenPGP::Message
        def sign(packet, hash='SHA256', keyid=nil)
          packet = unless packet.is_a?(OpenPGP::Packet) || packet.is_a?(OpenPGP::Message)
            if @key
              OpenPGP::Packet::LiteralData.new(:data => packet, :timestamp => Time.now.to_i)
            else
              OpenPGP::Message::parse(packet)
            end
          else
            packet
          end

          if packet.is_a?(OpenPGP::Packet::SecretKey) || packet.is_a?(::OpenSSL::PKey::RSA) \
             || (packet.is_a?(Enumerable) && packet.first.is_a?(OpenPGP::Packet::SecretKey))
            m = @message
            k = packet
          else
            m = packet
            k = @key
          end

          return nil unless k && m # Missing some data

          m = m.signature_and_data.first if m.is_a?(OpenPGP::Message)

          unless k.is_a?(::OpenSSL::PKey::RSA)
            k = self.class.new(k)
            keyid = k.key.fingerprint[-16,16] unless keyid
            k = k.rsa_key(keyid)
          end

          sig = OpenPGP::Packet::Signature.new(:version => 4,
            :key_algorithm => OpenPGP::Algorithm::Asymmetric::RSA,
            :hash_algorithm => OpenPGP::Digest::for(hash).to_i)
          sig.hashed_subpackets << OpenPGP::Packet::Signature::Issuer.new(keyid)
          sig.hashed_subpackets << OpenPGP::Packet::Signature::SignatureCreationTime.new(Time.now.to_i)
          sig.sign_data(m, {'RSA' => {hash => lambda {|m| k.sign(hash, m)}}})
          OpenPGP::Message.new([sig, m])
        end

        ##
        # @param  packet message with key/userid packets to sign (@key must be set)
        # @param  [String] hash name of hash function to use (default SHA256)
        # @param  [String] keyid id of key to use (if there is more than one)
        # @return OpenPGP::Message
        def sign_key_userid(packet, hash='SHA256', keyid=nil)
          if packet.is_a?(String)
            packet = OpenPGP::Message.parse(packet)
          elsif !packet.is_a?(OpenPGP::Message)
            packet = OpenPGP::Message.new(packet)
          end

          return nil unless @key && packet # Missing some data

          keyid = key.fingerprint[-16,16] unless keyid

          sig = packet.signature_and_data[1]
          unless sig
            sig = OpenPGP::Packet::Signature.new(:version => 4,
              :key_algorithm => OpenPGP::Algorithm::Asymmetric::RSA,
              :hash_algorithm => OpenPGP::Digest::for(hash).to_i,
              :type => 0x13)
            sig.hashed_subpackets << OpenPGP::Packet::Signature::SignatureCreationTime.new(Time.now.to_i)
            sig.hashed_subpackets << OpenPGP::Packet::Signature::KeyFlags.new(0x01 | 0x02)
            sig.unhashed_subpackets << OpenPGP::Packet::Signature::Issuer.new(keyid)
            packet << sig
          end
          sig.sign_data(packet, {'RSA' => {hash => lambda {|m| rsa_key.sign(hash, m)}}})

          packet
        end

        ##
        # @param  packet
        # @return [OpenSSL::PKey::RSA]
        def self.convert_key(packet)
          # packet is already an key
          return packet if packet.is_a?(::OpenSSL::PKey::RSA)
          unless packet.is_a?(Hash)
            # Get the first item in a message
            packet = packet.first if packet.is_a?(Enumerable)
            # TODO: Error if packet.algorithm not RSA
            packet = packet.key # Get key material
          end

          # Create blank key and fill the fields
          key = ::OpenSSL::PKey::RSA.new
          packet.each {|k,v|
            next if k == :u # OpenSSL doesn't call it that
            if v.is_a?(Numeric)
              v = ::OpenSSL::BN.new(v.to_s)
            elsif !(v.is_a?(::OpenSSL::BN))
              # Convert the byte string to an OpenSSL::BN
              v = v.reverse.enum_for(:each_char).enum_for(:each_with_index) \
                .inject(::OpenSSL::BN.new('0')) {|c, (b,i)|
                  c + (b.force_encoding('binary').ord << i*8)
                }
            end
            key.send("#{k}=".intern, v)
          }
          key
        end
      end

      ##
      # @private
      module Random #:nodoc:
        def number(bits = 32, options = {})
          ::OpenSSL::BN.rand(bits)
        end

        def prime(bits, options = {})
          ::OpenSSL::BN.generate_prime(bits, options[:safe])
        end

        def bytes(count, &block)
          ::OpenSSL::Random.random_bytes(count)
        end
      end

      ##
      # @private
      module Digest #:nodoc:
        def size
          ::OpenSSL::Digest.new(algorithm.to_s).digest_length
        end

        def hexdigest(data)
          ::OpenSSL::Digest.hexdigest(algorithm.to_s, data).upcase
        end

        def digest(data)
          ::OpenSSL::Digest.digest(algorithm.to_s, data)
        end
      end

      ##
      # @private
      module Cipher #:nodoc:
        # TODO
      end
    end
  end
end
