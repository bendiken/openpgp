module OpenPGP
  ##
  # OpenPGP message.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-11
  # @see http://tools.ietf.org/html/rfc4880#section-11.3
  class Message
    include Enumerable

    # @return [Array<Packet>]
    attr_accessor :packets

    ##
    # Creates an encrypted OpenPGP message.
    #
    # @param  [Object]                 data
    # @param  [Hash{Symbol => Object}] options
    # @return [Message]
    def self.encrypt(data, options = {}, &block)
      if options[:symmetric]
        key    = (options[:key]    || S2K::DEFAULT.new(options[:passphrase]))
        cipher = (options[:cipher] || Cipher::DEFAULT).new(key)

        msg    = self.new do |msg|
          msg << Packet::SymmetricSessionKey.new(:algorithm => cipher.identifier, :s2k => key)
          msg << Packet::EncryptedData.new do |packet|
            plaintext = self.write do |msg|
              case data
                when Message then data.each { |packet| msg << packet }
                when Packet  then msg << data
                else msg << Packet::LiteralData.new(:data => data)
              end
            end
            packet.data = cipher.encrypt(plaintext)
          end
        end

        block_given? ? block.call(msg) : msg
      else
        raise NotImplementedError # TODO
      end
    end

    ##
    # @param  [Object]                 data
    # @param  [Hash{Symbol => Object}] options
    # @return [Object]
    def self.decrypt(data, options = {}, &block)
      raise NotImplementedError # TODO
    end

    ##
    # Parses an OpenPGP message.
    #
    # @param  [Buffer, #to_str] data
    # @return [Message]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.1
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      data = Buffer.new(data.to_str) if data.respond_to?(:to_str)

      msg = self.new
      until data.eof?
        if packet = OpenPGP::Packet.parse(data)
          msg << packet
        else
          raise "Invalid OpenPGP message data at position #{data.pos}"
        end
      end
      msg
    end

    ##
    # @return [IO, #write] io
    # @return [void]
    def self.write(io = nil, &block)
      data = self.new(&block).to_s
      io.respond_to?(:write) ? io.write(data) : data
    end

    ##
    # @param  [Array<Packet>] packets
    def initialize(*packets, &block)
      @packets = packets.flatten
      block.call(self) if block_given?
    end

    def signature_and_data(index=0)
      msg = self
      msg = msg.first while msg.first.is_a?(OpenPGP::Packet::CompressedData)
      signature_packet = data_packet = nil
      i = 0
      msg.each { |packet|
        if packet.is_a?(OpenPGP::Packet::Signature)
          signature_packet = packet if i == index
          i += 1
        elsif packet.is_a?(OpenPGP::Packet::LiteralData)
          data_packet = packet
        end
        break if signature_packet && data_packet
      }
      [signature_packet, data_packet]
    end

    ##
    # @param  verifiers a Hash of callables formatted like {'RSA' => {'SHA256' => callable}} that take two parameters: message and signature
    # @param  index signature number to verify (if more than one)
    def verify(verifiers, index=0)
      signature_packet, data_packet = signature_and_data(index)
      return nil unless signature_packet && data_packet # No signature or no data
      verifier = verifiers[signature_packet.key_algorithm_name][signature_packet.hash_algorithm_name]
      return nil unless verifier # No verifier
      data_packet.normalize
      verifier.call(data_packet.data + signature_packet.trailer, signature_packet.fields)
    end

    ##
    # @yield  [packet]
    # @yieldparam [Packet] packet
    # @return [Enumerator]
    def each(&block) # :yields: packet
      packets.each(&block)
    end

    ##
    # @return [Array<Packet>]
    def to_a
      packets.to_a
    end

    ##
    # @param  [Packet] packet
    # @return [self]
    def <<(packet)
      packets << packet
    end

    ##
    # @return [Boolean]
    def empty?
      packets.empty?
    end

    ##
    # @return [Integer]
    def size
      inject(0) { |sum, packet| sum + packet.size }
    end

    ##
    # @return [String]
    def to_s
      Buffer.write do |buffer|
        packets.each do |packet|
          buffer.write_bytes(packet.to_s)
        end
      end
    end
  end
end
