if RUBY_VERSION < '1.8.7'
  # @see http://rubygems.org/gems/backports
  begin
    require 'backports/1.8.7'
  rescue LoadError
    begin
      require 'rubygems'
      require 'backports/1.8.7'
    rescue LoadError
      abort "OpenPGP.rb requires Ruby 1.8.7 or the Backports gem (hint: `gem install backports')."
    end
  end
end

unless 1.respond_to?(:ord)
  class Numeric
    def ord
      to_i
    end
  end
end

module OpenPGP
  require 'openpgp/util'

  autoload :Algorithm, 'openpgp/algorithm'
  autoload :Armor,     'openpgp/armor'
  autoload :Buffer,    'openpgp/buffer'
  autoload :Cipher,    'openpgp/cipher'
  autoload :Digest,    'openpgp/digest'
  autoload :Engine,    'openpgp/engine'
  autoload :Message,   'openpgp/message'
  autoload :Packet,    'openpgp/packet'
  autoload :Random,    'openpgp/random'
  autoload :S2K,       'openpgp/s2k'
  autoload :VERSION,   'openpgp/version'
end

OpenPGP::Engine::OpenSSL.install!
