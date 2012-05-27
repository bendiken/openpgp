module OpenPGP
  ##
  # Alias for {OpenPGP::Armor.encode}.
  def self.enarmor(data, marker = :message, options = {})
    Armor.encode(data, marker, options)
  end

  ##
  # Alias for {OpenPGP::Armor.decode}.
  def self.dearmor(text, marker = nil, options = {})
    Armor.decode(text, marker, options)
  end

  ##
  # Alias for {OpenPGP::Message.encrypt}.
  def self.encrypt(data, options = {})
    (msg = Message.encrypt(data, options)) ? msg.to_s : nil
  end

  ##
  # Alias for {OpenPGP::Message.decrypt}.
  def self.decrypt(data, options = {})
    raise NotImplementedError # TODO
  end

  ##
  # Alias for {OpenPGP::Message.sign}.
  def self.sign
    raise NotImplementedError # TODO
  end

  ##
  # Alias for {OpenPGP::Message.verify}.
  def self.verify
    raise NotImplementedError # TODO
  end

  ##
  # @see http://tools.ietf.org/html/rfc4880#section-6.1
  CRC24_INIT = 0x00b704ce
  CRC24_POLY = 0x01864cfb

  ##
  # @param  [String] data
  # @return [Integer]
  # @see    http://tools.ietf.org/html/rfc4880#section-6
  # @see    http://tools.ietf.org/html/rfc4880#section-6.1
  def self.crc24(data)
    crc = CRC24_INIT
    data.each_byte do |octet|
      crc ^= octet << 16
      8.times do
        crc <<= 1
        crc ^= CRC24_POLY if (crc & 0x01000000).nonzero?
      end
    end
    crc &= 0x00ffffff
  end

  ##
  # Returns the bit length of a multiprecision integer (MPI).
  #
  # @param  [String] data
  # @return [Integer]
  # @see    http://tools.ietf.org/html/rfc4880#section-3.2
  def self.bitlength(data)
    data = data.split(//)
    while (f = data.shift) == '\0'; end
    return 0 unless f
    Math.log(f.ord, 2).floor + 1 + (data.length*8)
  end

  ##
  # Returns the network-byte-order representation of n
  # @param [Numeric] n
  # @return [String]
  def self.bn2bin(n)
    raise RangeError.new('Cannot convert negative number') if n < 0
    bytes = n.size

    # Mask off any leading 0 bytes
    mask = 0xFF << (8 * bytes - 1)
    while (mask & n) == 0
      mask >>= 8
      bytes -= 1
    end

    result = []
    bits_left = n
    until bits_left == 0
      result << (bits_left & 0xFF).chr
      bits_left >>= 8
    end
    result.reverse.join
  end

  ##
  # Returns the multiplicative inverse of b, mod m
  # @param [Numeric] b
  # @param [Numeric] m
  # @return [Numeric]
  def self.egcd(b,m,recLevel=0)
    if b % m == 0
      [0,1]
    else
      tmpVal = egcd(m, b % m, recLevel+1)
      tmpVal2 = [tmpVal[1], tmpVal[0]-tmpVal[1] * ((b/m).to_i)]
      if recLevel == 0
        tmpVal2[0] % m
      else
        tmpVal2
      end
    end
  end

end
