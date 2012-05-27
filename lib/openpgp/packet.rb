require 'zlib'

module OpenPGP
  ##
  # OpenPGP packet.
  #
  # @see http://tools.ietf.org/html/rfc4880#section-4.1
  # @see http://tools.ietf.org/html/rfc4880#section-4.3
  class Packet
    attr_accessor :tag, :size, :data

    ##
    # Returns the implementation class for a packet tag.
    #
    # @param  [Integer, #to_i] tag
    # @return [Class]
    def self.for(tag)
      @@tags[tag.to_i] || self
    end

    ##
    # Returns the packet tag for this class.
    #
    # @return [Integer]
    def self.tag
      @@tags.index(self)
    end

    ##
    # Parses an OpenPGP packet.
    #
    # @param  [Buffer, #to_str] data
    # @return [Packet]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2
    def self.parse(data)
      data = Buffer.new(data.to_str) if data.respond_to?(:to_str)

      unless data.eof?
        new = ((tag = data.getbyte) & 64).nonzero? # bit 6 indicates new packet format if set
        data.ungetbyte(tag) rescue data.ungetc(tag.ord) # FIXME in backports/1.8.7
        send(new ? :parse_new_format : :parse_old_format, data)
      end
    end

    ##
    # Parses a new-format (RFC 4880) OpenPGP packet.
    #
    # @param  [Buffer, #to_str] data
    # @return [Packet]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2.2
    def self.parse_new_format(data)
      tag = data.getbyte & 63
      len = data.getbyte

      case len
        when 0..191   # 4.2.2.1. One-Octet Lengths
          data_length = len
        when 192..223 # 4.2.2.2. Two-Octet Lengths
          data_length = ((len - 192) << 8) + data.getbyte + 192
        when 224..254 # 4.2.2.4. Partial Body Lengths
          data_length = 1 << (len & 0x1f)
        when 255      # 4.2.2.3. Five-Octet Lengths
          data_length = (data.getbyte << 24) | (data.getbyte << 16) | (data.getbyte << 8) | data.getbyte
      end

      Packet.for(tag).parse_body(Buffer.new(data.read(data_length)), :tag => tag)
    end

    ##
    # Parses an old-format (PGP 2.6.x) OpenPGP packet.
    #
    # @param  [Buffer, #to_str] data
    # @return [Packet]
    # @see    http://tools.ietf.org/html/rfc4880#section-4.2.1
    def self.parse_old_format(data)
      len = (tag = data.getbyte) & 3
      tag = (tag >> 2) & 15

      case len
        when 0 # The packet has a one-octet length. The header is 2 octets long.
          data_length = data.getbyte
        when 1 # The packet has a two-octet length. The header is 3 octets long.
          data_length = data.read(2).unpack('n').first
        when 2 # The packet has a four-octet length. The header is 5 octets long.
          data_length = data.read(4).unpack('N').first
        when 3 # The packet is of indeterminate length. The header is 1 octet long.
          data_length = false # read to EOF
        else
          raise "Invalid OpenPGP packet length-type: expected 0..3 but got #{len}"
      end

      Packet.for(tag).parse_body(Buffer.new(data_length ? data.read(data_length) : data.read), :tag => tag)
    end

    ##
    # @param  [Buffer]                 body
    # @param  [Hash{Symbol => Object}] options
    # @return [Packet]
    def self.parse_body(body, options = {})
      self.new(options)
    end

    ##
    # @param  [Hash{Symbol => Object}] options
    def initialize(options = {}, &block)
      options.each { |k, v| send("#{k}=", v) }
      block.call(self) if block_given?
    end

    def to_s
      data = header_and_body
      data[:header] + (data[:body] || '')
    end

    ##
    # @return [Integer]
    def size() body.size end

    ##
    # @return [Hash]
    def header_and_body
      body = self.body # Get body first, we will need it's length
      tag = (self.class.tag | 0xC0).chr # First two bits are 1 for new packet format
      size = 255.chr + [body ? body.length : 0].pack('N') # Use 5-octet lengths
      {:header => tag + size, :body => body}
    end

    ##
    # @return [String]
    def body
      respond_to?(:write_body) ? Buffer.write { |buffer| write_body(buffer) } : ""
    end

    ##
    # OpenPGP Public-Key Encrypted Session Key packet (tag 1).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.1
    # @see http://tools.ietf.org/html/rfc4880#section-13.1
    class AsymmetricSessionKey < Packet
      attr_accessor :version, :key_id, :algorithm

      def self.parse_body(body, options = {})
        case version = body.read_byte
          when 3
            self.new(:version => version, :key_id => body.read_number(8, 16), :algorithm => body.read_byte)
            # TODO: read the encrypted session key.
          else
            raise "Invalid OpenPGP public-key ESK packet version: #{version}"
        end
      end
    end

    ##
    # OpenPGP Signature packet (tag 2).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.2
    class Signature < Packet
      attr_accessor :version, :type
      attr_accessor :key_algorithm, :hash_algorithm
      attr_accessor :key_id
      attr_accessor :fields
      attr_accessor :hashed_subpackets, :unhashed_subpackets
      attr_accessor :hash_head, :trailer

      def initialize(options={}, &blk)
        @hashed_subpackets = []
        @unhashed_subpackets = []
        super(options, &blk)
      end

      def self.parse_body(body, options = {})
        @hashed_subpackets = @unhashed_subpackets = []
        case version = body.read_byte
          when 3 then self.new(:version => 3).send(:read_v3_signature, body)
          when 4 then self.new(:version => 4).send(:read_v4_signature, body)
          else raise "Invalid OpenPGP signature packet version: #{version}"
        end
      end

      ##
      # @params  [OpenPGP::Packet::LiteralData | OpenPGP::Message] m
      # @params  [Hash] signers in the same format as verifiers for Message
      def sign_data(m, signers)
        data = if m.is_a?(LiteralData)
          self.type = m.format == :b ? 0x00 : 0x01
          m.normalize # Line endings
          m.data
        else
          # m must be message where PublicKey is first, UserID is second
          m = m.to_a # Se we can index into it
          key = m[0].fingerprint_material.join
          user_id = m[1].body
          key + 0xB4.chr + [user_id.length].pack('N') + user_id
        end
        update_trailer
        signer = signers[key_algorithm_name][hash_algorithm_name]
        self.fields = signer.call(data + trailer)
        self.fields = [fields] unless fields.is_a?(Enumerable)
        self.hash_head = fields.first[0,2].unpack('n').first
      end

      def key_algorithm_name
          name = OpenPGP::Algorithm::Asymmetric::constants.select do |const|
            OpenPGP::Algorithm::Asymmetric::const_get(const) == key_algorithm
          end.first
          name = :RSA if name == :RSA_S || name == :RSA_E
          name.to_s
      end

      def hash_algorithm_name
        OpenPGP::Digest::for(hash_algorithm).algorithm.to_s
      end

      def issuer
        packet = (hashed_subpackets + unhashed_subpackets).select {|packet|
          packet.is_a?(OpenPGP::Packet::Signature::Issuer)
        }.first
        if packet
          packet.data
        else
          key_id
        end
      end

      def update_trailer
        @trailer = body(true)
      end

      def body(trailer=false)
        body = 4.chr + type.chr + key_algorithm.chr + hash_algorithm.chr

        sub = hashed_subpackets.inject('') {|c,p| c + p.to_s}
        body << [sub.length].pack('n') + sub

        # The trailer is just the top of the body plus some crap
        return body + 4.chr + 0xff.chr + [body.length].pack('N') if trailer

        sub = unhashed_subpackets.inject('') {|c,p| c + p.to_s}
        body << [sub.length].pack('n') + sub

        body << [hash_head].pack('n')

        fields.each {|data|
          body << [OpenPGP.bitlength(data)].pack('n')
          body << data
        }
        body
      end

      protected

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.2
        def read_v3_signature(body)
          raise "Invalid OpenPGP signature packet V3 header" if body.read_byte != 5
          @type, @timestamp, @key_id = body.read_byte, body.read_number(4), body.read_number(8, 16)
          @key_algorithm, @hash_algorithm = body.read_byte, body.read_byte
          @hash_head = body.read_bytes(2)
          read_signature(body)
          self
        end

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.3
        def read_v4_signature(body)
          @type = body.read_byte
          @key_algorithm, @hash_algorithm = body.read_byte, body.read_byte
          # We store exactly the original trailer for doing verifications
          @trailer = 4.chr + type.chr + key_algorithm.chr + hash_algorithm.chr
          hashed_count = body.read_number(2)
          hashed_data = body.read_bytes(hashed_count)
          @trailer << [hashed_count].pack('n') + hashed_data + 4.chr + 0xff.chr + [6 + hashed_count].pack('N')
          @hashed_subpackets = read_subpackets(Buffer.new(hashed_data))
          unhashed_count = body.read_number(2)
          unhashed_data = body.read_bytes(unhashed_count)
          @unhashed_subpackets = read_subpackets(Buffer.new(unhashed_data))
          @hash_head = body.read_bytes(2).unpack('n').first
          read_signature(body)
          self
        end

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.3.1
        def read_subpackets(buf)
          packets = []
          until buf.eof?
            if packet = read_subpacket(buf)
              packets << packet
            else
              raise "Invalid OpenPGP message data at position #{buf.pos} in signature subpackets"
            end
          end
          packets
        end

        def read_subpacket(buf)
          length = buf.read_byte.ord
          length_of_length = 1
          # if len < 192 One octet length, no furthur processing
          if length > 190 && length < 255 # Two octet length
            length_of_length = 2
            length = ((length - 192) << 8) + buf.read_byte.ord + 192
          end
          if length == 255 # Five octet length
            length_of_length = 5
            length = buf.read_unpacked(4, 'N')
          end

          tag = buf.read_byte.ord
          critical = (tag & 0x80) != 0
          tag &= 0x7F
          self.class.const_get(self.class.constants.select {|t|
            self.class.const_get(t).const_defined?(:TAG) && \
            self.class.const_get(t)::TAG == tag
          }.first).parse_body(Buffer.new(buf.read(length-1)), :tag => tag)
        rescue Exception
          nil # Parse error, return no subpacket
        end

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.2
        def read_signature(body)
          case key_algorithm
            when Algorithm::Asymmetric::RSA
              @fields = [body.read_mpi]
            when Algorithm::Asymmetric::DSA
              @fields = [body.read_mpi, body.read_mpi]
            else
              raise "Unknown OpenPGP signature packet public-key algorithm: #{key_algorithm}"
          end
        end

        class Subpacket < Packet
          attr_reader :data
          def header_and_body
            b = body
            # Use 5-octet lengths
            size = 255.chr + [body.length+1].pack('N')
            tag = self.class.const_get(:TAG).chr
            {:header => size + tag, :body => body}
          end
        end

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.3.4
        class SignatureCreationTime < Subpacket
          TAG = 2
          def initialize(time=nil)
            super()
            @data = time || Time.now.to_i
          end

          def self.parse_body(body, options={})
            self.new(body.read_timestamp)
          end

          def body
            [@data].pack('N')
          end
        end
        class SignatureExpirationTime < Subpacket
          TAG = 3
          def initialize(time=nil)
            super()
            @data = time || 0
          end

          def self.parse_body(body, options={})
            self.new(body.read_timestamp)
          end

          def body
            [@data].pack('N')
          end
        end
        class ExportableCertification < Subpacket
          TAG = 4
        end
        class TrustSignature < Subpacket
          TAG = 5
        end
        class RegularExpression < Subpacket
          TAG = 6
        end
        class Revocable < Subpacket
          TAG = 7
        end
        class KeyExpirationTime < Subpacket
          TAG = 9
          def initialize(time=nil)
            super()
            @data = time || Time.now.to_i
          end

          def self.parse_body(body, options={})
            self.new(body.read_timestamp)
          end

          def body
            [@data].pack('N')
          end
        end
        class PreferredSymmetricAlgorithms < Subpacket
          TAG = 11
        end
        class RevocationKey < Subpacket
          TAG = 12
        end

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.3.5
        class Issuer < Subpacket
          TAG = 16
          def initialize(keyid=nil)
            super()
            @data = keyid
          end

          def self.parse_body(body, options={})
            data = ''
            8.times do # Store KeyID in Hex
              data << '%02X' % body.read_byte.ord
            end
            self.new(data)
          end

          def body
            b = ''
            @data.enum_for(:each_char).each_slice(2) do |i|
              b << i.join.to_i(16).chr
            end
            b
          end
        end
        class NotationData < Subpacket
          TAG = 20
        end
        class PreferredHashAlgorithms < Subpacket
          TAG = 21
        end
        class PreferredCompressionAlgorithms < Subpacket
          TAG = 22
        end

        ##
        # @see http://tools.ietf.org/html/rfc4880#section-5.2.3.18
        class KeyServerPreferences < Subpacket
          TAG = 23
        end
        class PreferredKeyServer < Subpacket
          TAG = 24
          def initialize(uri=nil)
            super()
            @data = uri
          end

          def self.parse_body(body, options={})
            self.new(body.read)
          end

          def body
            @data
          end
        end
        class PrimaryUserID < Subpacket
          TAG = 25
        end
        class PolicyURI < Subpacket
          TAG = 26
        end
        class KeyFlags < Subpacket
          TAG = 27
          attr_accessor :flags

          def initialize(*flags)
            super()
            @flags = flags.flatten
          end

          def self.parse_body(body, options={})
            flags = []
            until body.eof?
              flags << body.read_byte.ord
            end
            self.new(flags)
          end

          def body
            flags.map {|f| f.chr}.join
          end
        end
        class SignersUserID < Subpacket
          TAG = 28
        end
        class ReasonforRevocation < Subpacket
          TAG = 29
        end
        class Features < KeyFlags
          TAG = 30
        end
        class SignatureTarget < Subpacket
          TAG = 31
        end
        class EmbeddedSignature < Subpacket
          TAG = 32
        end
    end

    ##
    # OpenPGP Symmetric-Key Encrypted Session Key packet (tag 3).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.3
    class SymmetricSessionKey < Packet
      attr_accessor :version, :algorithm, :s2k

      def self.parse_body(body, options = {})
        case version = body.read_byte
          when 4
            self.new({:version => version, :algorithm => body.read_byte, :s2k => body.read_s2k}.merge(options))
          else
            raise "Invalid OpenPGP symmetric-key ESK packet version: #{version}"
        end
      end

      def initialize(options = {}, &block)
        defaults = {
          :version   => 4,
          :algorithm => Cipher::DEFAULT.to_i,
          :s2k       => S2K::DEFAULT.new,
        }
        super(defaults.merge(options), &block)
      end

      def write_body(buffer)
        buffer.write_byte(version)
        buffer.write_byte(algorithm.to_i)
        buffer.write_s2k(s2k)
      end
    end

    ##
    # OpenPGP One-Pass Signature packet (tag 4).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.4
    class OnePassSignature < Packet
      # TODO
    end

    ##
    # OpenPGP Public-Key packet (tag 6).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.1
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class PublicKey < Packet
      attr_accessor :size
      attr_accessor :version, :timestamp, :algorithm
      attr_accessor :key, :key_id, :fingerprint

      #def parse(data) # FIXME
      def self.parse_body(body, options = {})
        case version = body.read_byte
          when 2, 3
            # TODO
          when 4
            packet = self.new(:version => version, :timestamp => body.read_timestamp, :algorithm => body.read_byte, :key => {}, :size => body.size)
            packet.read_key_material(body)
            packet
          else
            raise "Invalid OpenPGP public-key packet version: #{version}"
        end
      end

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
      def read_key_material(body)
        key_fields.each { |field| key[field] = body.read_mpi }
        @key_id = fingerprint[-8..-1]
      end

      def key_fields
        case algorithm
          when Algorithm::Asymmetric::RSA   then [:n, :e]
          when Algorithm::Asymmetric::ELG_E then [:p, :g, :y]
          when Algorithm::Asymmetric::DSA   then [:p, :q, :g, :y]
          else raise "Unknown OpenPGP key algorithm: #{algorithm}"
        end
      end

      def fingerprint_material
        case version
          when 2, 3
            [key[:n], key[:e]].join
          when 4
            material = key_fields.map do |key_field|
              [[OpenPGP.bitlength(key[key_field])].pack('n'), key[key_field]]
            end.flatten.join
            [0x99.chr, [material.length + 6].pack('n'), version.chr, [timestamp].pack('N'), algorithm.chr, material]
        end
      end

      ##
      # @see http://tools.ietf.org/html/rfc4880#section-12.2
      # @see http://tools.ietf.org/html/rfc4880#section-3.3
      def fingerprint
        @fingerprint ||= case version
          when 2, 3
            Digest::MD5.hexdigest(fingerprint_material.join).upcase
          when 4
            Digest::SHA1.hexdigest(fingerprint_material.join).upcase
        end
      end

      def body
        case version
          when 2, 3
            # TODO
          when 4
            fingerprint_material[2..-1].join
        end
      end
    end

    ##
    # OpenPGP Public-Subkey packet (tag 14).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.2
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.2
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class PublicSubkey < PublicKey
      # TODO
    end

    ##
    # OpenPGP Secret-Key packet (tag 5).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.3
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.3
    # @see http://tools.ietf.org/html/rfc4880#section-11.2
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class SecretKey < PublicKey
      attr_accessor :s2k_useage, :symmetric_type, :s2k_type, :s2k_hash_algorithm
      attr_accessor :s2k_salt, :s2k_count, :encrypted_data, :data

      def self.parse_body(body, options={})
        key = super # All the fields from PublicKey
        data = {:s2k_useage => body.read_byte.ord}
        if data[:s2k_useage] == 255 || data[:s2k_useage] == 254
          data[:symmetric_type] = body.read_byte.ord
          data[:s2k_type] = body.read_byte.ord
          data[:s2k_hash_algorithm] = self.read_byte.ord
          if data[:s2k_type] == 1 || data[:s2k_type] == 3
            data[:s2k_salt] = body.read_bytes(8)
          end
          if data[:s2k_type] == 3
            c = self.read_byte.ord
            data[:s2k_count] = (16 + (c & 15)).floor << ((c >> 4) + 6)
          end
        elsif data[:s2k_useage] > 0
          data[:symmetric_type] = data[:s2k_useage]
        end
       if data[:s2k_useage] > 0
         # TODO: IV of the same length as cipher's block size
         data[:encrypted_data] = body.read # Rest of input is MPIs and checksum (encrypted)
       else
         data[:data] = body.read # Rest of input is MPIs and checksum
       end
       data.each {|k,v| key.send("#{k}=", v) }
       key.key_from_data
       key
      end

      def key_from_data
        return nil unless data # Not decrypted yet
        body = Buffer.new(data)
        secret_key_fields.each {|mpi|
          self.key[mpi] = body.read_mpi
        }
        # TODO: Validate checksum?
        if s2k_useage == 254 # 20 octet sha1 hash
          @private_hash = body.read_bytes(20)
        else # 2 octet checksum
          @private_hash = body.read_bytes(2)
        end
      end

      def secret_key_fields
        case algorithm
          when Algorithm::Asymmetric::RSA,
               Algorithm::Asymmetric::RSA_E,
               Algorithm::Asymmetric::RSA_S then [:d, :p, :q, :u]
          when Algorithm::Asymmetric::ELG_E then [:x]
          when Algorithm::Asymmetric::DSA   then [:x]
          else raise "Unknown OpenPGP key algorithm: #{algorithm}"
        end
      end

      def body
        super + s2k_useage.to_i.chr + \
        if s2k_useage == 255 || s2k_useage == 254
          symmetric_type.chr + s2k_type.chr + s2k_hash_algorithm.chr + \
          (s2k_type == 1 || s2k_type == 3 ? s2k_salt : '')
          # (s2k_type == 3 ? reverse ugly bit manipulation
        end.to_s + if s2k_useage.to_i > 0
          encrypted_data
        else
          secret_material = secret_key_fields.map {|f| [OpenPGP.bitlength(key[f].to_s)].pack('n') + key[f].to_s}.join
        end + \
        if s2k_useage == 254 # SHA1 checksum
          # TODO
          "\0"*20
        else # 2-octet checksum
          # TODO, this design will not work for encrypted keys
          [secret_material.split(//).inject(0) {|chk, c|
            chk = (chk + c.ord) % 65536
          }].pack('n')
        end
      end
    end

    ##
    # OpenPGP Secret-Subkey packet (tag 7).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.1.4
    # @see http://tools.ietf.org/html/rfc4880#section-5.5.3
    # @see http://tools.ietf.org/html/rfc4880#section-11.2
    # @see http://tools.ietf.org/html/rfc4880#section-12
    class SecretSubkey < SecretKey
      # TODO
    end

    ##
    # OpenPGP Compressed Data packet (tag 8).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.6
    class CompressedData < Packet
      include Enumerable
      attr_accessor :algorithm, :data

      def initialize(algorithm=nil, data=nil)
        @algorithm = algorithm
        @data = data
      end

      def self.parse_body(body, options={})
        algorithm = body.read_byte.ord
        data = body.read
        data = Message::parse(case algorithm
          when 0 # Uncompressed
            data
          when 1 # ZIP
            Zlib::Inflate.new(-Zlib::MAX_WBITS).inflate(data)
          when 2 # ZLIB
            Zlib::Inflate.inflate(data)
          when 3 # BZIP2
            # TODO
        end)
        self.new(algorithm, data)
      end

      def body
        body = algorithm.chr
        body << case algorithm
          when 0 # Uncompressed
            data.to_s
          when 1 # ZIP
            Zlib::Deflate.new(nil, -Zlib::MAX_WBITS).deflate(data.to_s, Zlib::FINISH)
          when 2 # ZLIB
            Zlib::Deflate.deflate(data.to_s)
          when 3 # BZIP2
            # TODO
        end
      end

      # Proxy onto embedded OpenPGP message
      def each(&cb)
        @data.each &cb
      end
    end

    ##
    # OpenPGP Symmetrically Encrypted Data packet (tag 9).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.7
    class EncryptedData < Packet
      attr_accessor :data

      def self.parse_body(body, options = {})
        self.new({:data => body.read}.merge(options))
      end

      def initialize(options = {}, &block)
        super(options, &block)
      end

      def write_body(buffer)
        buffer.write(data)
      end
    end

    ##
    # OpenPGP Marker packet (tag 10).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.8
    class Marker < Packet
      # TODO
    end

    ##
    # OpenPGP Literal Data packet (tag 11).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.9
    class LiteralData < Packet
      attr_accessor :format, :filename, :timestamp, :data

      def self.parse_body(body, options = {})
        defaults = {
          :format    => body.read_byte.chr.to_sym,
          :filename  => body.read_string,
          :timestamp => body.read_timestamp,
          :data      => body.read,
        }
        self.new(defaults.merge(options))
      end

      def initialize(options = {}, &block)
        defaults = {
          :format    => :b,
          :filename  => "",
          :timestamp => 0,
          :data      => "",
        }
        super(defaults.merge(options), &block)
      end

      def normalize
        # Normalize line endings
        if format == :u || format == :t
          @data.gsub!(/\r\n/, "\n")
          @data.gsub!(/\r/, "\n")
          @data.gsub!(/\n/, "\r\n")
        end
      end

      def write_body(buffer)
        buffer.write_byte(format)
        buffer.write_string(filename)
        buffer.write_timestamp(timestamp)
        buffer.write(data.to_s)
      end

      EYES_ONLY = '_CONSOLE'

      def eyes_only!() filename = EYES_ONLY end
      def eyes_only?() filename == EYES_ONLY end
    end

    ##
    # OpenPGP Trust packet (tag 12).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.10
    class Trust < Packet
      attr_accessor :data

      def self.parse_body(body, options = {})
        self.new({:data => body.read}.merge(options))
      end

      def write_body(buffer)
        buffer.write(data)
      end
    end

    ##
    # OpenPGP User ID packet (tag 13).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.11
    # @see http://tools.ietf.org/html/rfc2822
    class UserID < Packet
      attr_accessor :name, :comment, :email

      def self.parse_body(body, options = {})
        case body.read
          # User IDs of the form: "name (comment) <email>"
          when /^([^\(]+)\(([^\)]+)\)\s+<([^>]+)>$/
            self.new(:name => $1.strip, :comment => $2.strip, :email => $3.strip)
          # User IDs of the form: "name <email>"
          when /^([^<]+)\s+<([^>]+)>$/
            self.new(:name => $1.strip, :comment => nil, :email => $2.strip)
          # User IDs of the form: "name"
          when /^([^<]+)$/
            self.new(:name => $1.strip, :comment => nil, :email => nil)
          # User IDs of the form: "<email>"
          when /^<([^>]+)>$/
            self.new(:name => nil, :comment => nil, :email => $1.strip)
          else
            self.new(:name => nil, :comment => nil, :email => nil)
        end
      end

      def write_body(buffer)
        buffer.write(to_s)
      end

      def body
        text = []
        text << name if name
        text << "(#{comment})" if comment
        text << "<#{email}>" if email
        text.join(' ')
      end
    end

    ##
    # OpenPGP User Attribute packet (tag 17).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.12
    # @see http://tools.ietf.org/html/rfc4880#section-11.1
    class UserAttribute < Packet
      attr_accessor :packets

      # TODO
    end

    ##
    # OpenPGP Sym. Encrypted Integrity Protected Data packet (tag 18).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.13
    class IntegrityProtectedData < Packet
      attr_accessor :version

      def self.parse_body(body, options = {})
        case version = body.read_byte
          when 1
            self.new(:version => version) # TODO: read the encrypted data.
          else
            raise "Invalid OpenPGP integrity-protected data packet version: #{version}"
        end
      end
    end

    ##
    # OpenPGP Modification Detection Code packet (tag 19).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-5.14
    class ModificationDetectionCode < Packet
      # TODO
    end

    ##
    # OpenPGP Private or Experimental packet (tags 60..63).
    #
    # @see http://tools.ietf.org/html/rfc4880#section-4.3
    class Experimental < Packet; end

    protected
      ##
      # @see http://tools.ietf.org/html/rfc4880#section-4.3
      @@tags = {
         1 => AsymmetricSessionKey,      # Public-Key Encrypted Session Key
         2 => Signature,                 # Signature Packet
         3 => SymmetricSessionKey,       # Symmetric-Key Encrypted Session Key Packet
         4 => OnePassSignature,          # One-Pass Signature Packet
         5 => SecretKey,                 # Secret-Key Packet
         6 => PublicKey,                 # Public-Key Packet
         7 => SecretSubkey,              # Secret-Subkey Packet
         8 => CompressedData,            # Compressed Data Packet
         9 => EncryptedData,             # Symmetrically Encrypted Data Packet
        10 => Marker,                    # Marker Packet
        11 => LiteralData,               # Literal Data Packet
        12 => Trust,                     # Trust Packet
        13 => UserID,                    # User ID Packet
        14 => PublicSubkey,              # Public-Subkey Packet
        17 => UserAttribute,             # User Attribute Packet
        18 => IntegrityProtectedData,    # Sym. Encrypted and Integrity Protected Data Packet
        19 => ModificationDetectionCode, # Modification Detection Code Packet
        60 => Experimental,              # Private or Experimental Values
        61 => Experimental,              # Private or Experimental Values
        62 => Experimental,              # Private or Experimental Values
        63 => Experimental,              # Private or Experimental Values
      }
  end
end
