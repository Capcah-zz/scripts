require 'base64'
require 'openssl'
require 'set'
require 'net/http'
require './level3'
require 'stringio'

def sxor(s1,s2)
  return xor(s1.unpack("C*"),s2.unpack("C*")).pack("C*")
end
 
# Calculates SHA-1 message digest of _string_. Returns binary digest.
# For hexadecimal digest, use +*sha1(string).unpack('H*')+.
#--
# This is a simple, pure-Ruby implementation of SHA-1, following
# the algorithm in FIPS 180-1.
#++
def sha1(string,oldh=nil,offset=0)
  # functions and constants
  mask = 0xffffffff
  s = proc{|n, x| ((x << n) & mask) | (x >> (32 - n))}
  f = [
    proc {|b, c, d| (b & c) | (b.^(mask) & d)},
    proc {|b, c, d| b ^ c ^ d},
    proc {|b, c, d| (b & c) | (b & d) | (c & d)},
    proc {|b, c, d| b ^ c ^ d},
  ].freeze
  k = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6].freeze
 
  # initial hash
  h = (oldh)?oldh[0..-1] : [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]
 
  bit_len = (string.size+offset) << 3
  string += "\x80".force_encoding('ascii-8bit')
  while (string.size % 64) != 56
    string += "\0"
  end
  string = string.force_encoding('ascii-8bit') + [bit_len >> 32, bit_len & mask].pack("N2")
  if string.size % 64 != 0
    fail "failed to pad to correct length"
  end
 
  io = StringIO.new(string)
  block = ""
 
  while io.read(64, block)
    w = block.unpack("N16")
 
    # Process block.
    (16..79).each {|t| w[t] = s[1, w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]]}
 
    a, b, c, d, e = h
    t = 0
    4.times do |i|
      20.times do
        temp = (s[5, a] + f[i][b, c, d] + e + w[t] + k[i]) & mask
        a, b, c, d, e = temp, a, s[30, b], c, d
        t += 1
      end
    end
    [a,b,c,d,e].each_with_index {|x,i| h[i] = (h[i] + x) & mask}
  end
  h.pack("N5")
end

require 'stringio'
 
# Calculates MD4 message digest of _string_. Returns binary digest.
# For hexadecimal digest, use +*md4(str).unpack('H*')+.
def md4(string,oldh=nil,offset=0)
  # functions
  mask = (1 << 32) - 1
  f = proc {|x, y, z| x & y | x.^(mask) & z}
  g = proc {|x, y, z| x & y | x & z | y & z}
  h = proc {|x, y, z| x ^ y ^ z}
  r = proc {|v, s| (v << s).&(mask) | (v.&(mask) >> (32 - s))}
 
  # initial hash
  a, b, c, d = oldh ? oldh[0..-1] : [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
 
  bit_len = (string.size+offset) << 3
  string += "\x80".force_encoding('ascii-8bit')
  while ((string.size+offset) % 64) != 56
    string += "\0"
  end
  string = string.force_encoding('ascii-8bit') + [bit_len & mask, bit_len >> 32].pack("V2")
 
  if string.size % 64 != 0
    fail "failed to pad to correct length"
  end
 
  io = StringIO.new(string)
  block = ""
 
  while io.read(64, block)
    x = block.unpack("V16")
 
    # Process this block.
    aa, bb, cc, dd = a, b, c, d
    [0, 4, 8, 12].each {|i|
      a = r[a + f[b, c, d] + x[i],  3]; i += 1
      d = r[d + f[a, b, c] + x[i],  7]; i += 1
      c = r[c + f[d, a, b] + x[i], 11]; i += 1
      b = r[b + f[c, d, a] + x[i], 19]
    }
    [0, 1, 2, 3].each {|i|
      a = r[a + g[b, c, d] + x[i] + 0x5a827999,  3]; i += 4
      d = r[d + g[a, b, c] + x[i] + 0x5a827999,  5]; i += 4
      c = r[c + g[d, a, b] + x[i] + 0x5a827999,  9]; i += 4
      b = r[b + g[c, d, a] + x[i] + 0x5a827999, 13]
    }
    [0, 2, 1, 3].each {|i|
      a = r[a + h[b, c, d] + x[i] + 0x6ed9eba1,  3]; i += 8
      d = r[d + h[a, b, c] + x[i] + 0x6ed9eba1,  9]; i -= 4
      c = r[c + h[d, a, b] + x[i] + 0x6ed9eba1, 11]; i += 8
      b = r[b + h[c, d, a] + x[i] + 0x6ed9eba1, 15]
    }
    a = (a + aa) & mask
    b = (b + bb) & mask
    c = (c + cc) & mask
    d = (d + dd) & mask
  end
  [a, b, c, d].pack("V4")
end

class C25
  attr_accessor :ctx
  def initialize
    @key = "YELLOW SUBMARINE"
    @nonce = rand((1<<32)-1)
    @pchal = Net::HTTP.get(URI('http://cryptopals.com/static/challenge-data/25.txt')
            ).split.map{|x| Base64.decode64 x}.join("\n")
    puts @pchal
    @ctx = C18.encrypt @pchal,@key,@nonce
  end

  def attacker_edit(off,ntx)
    stream = C18.gstream(@nonce,@key,(off+ntx.size)/16)[off...off+ntx.size].pack("C*")
    @ctx[off...off+ntx.size] = sxor(stream,ntx)
  end

  def self.run
    oracle = C25.new
    ctx = oracle.ctx[0..-1]
    known = 'A'*ctx.size
    oracle.attacker_edit 0,known
    new_ctx = oracle.ctx
    #puts sxor(sxor(new_ctx,known),ctx)
  end
end

class C26
  attr_accessor :ctx
  def initialize(msg)
    @msg = "comment1=cooking%20MCs;userdata="+msg+";comment2=%20like%20a%20pound%20of%20bacon"
    @key = "YELLOW SUBMARINE"
    @nonce = rand((1<<32)-1)
    @ctx = C18.encrypt @msg,@key,@nonce
  end

  def check_admin(ctx)
    ptx = C18.decrypt ctx,@key,@nonce
    return ptx.index('admin=true')
  end

  def self.run
    chall = C26.new '' #don't actually need any text
    ctx = chall.ctx
    fiddler = sxor('admin=true'+';'*22,"comment1=cooking%20MCs;userdata=")
    puts 'Done!' if chall.check_admin(sxor(fiddler,ctx))
  end
end

class C27
  def self.run
#    enc = OpenSSL::Cipher.new 'AES-128-CBC'
#    enc.encrypt
#    enc.key = enc.iv = 'yellow submarine'
#    trash = enc.update('n'*16)
    trash = 'k'*16
    agent = OpenSSL::Cipher.new 'AES-128-CBC'
    agent.decrypt
    agent.key = agent.iv = 'yellow submarine'
    ptx = [agent.update(trash),agent.update(trash),agent.update(trash)][1..-1]
    puts sxor(sxor(ptx[0],ptx.last),trash)
  end
end

class C28
  attr_accessor :digest
  def initialize(msg,key='a happy key')
    @digest = sha1(key+msg)
    @key = key
  end
  def check(msg,hash=nil)
    return @digest == sha1(@key+msg.force_encoding('ascii-8bit')) unless hash
    return sha1(@key+msg.force_encoding('ascii-8bit')) == hash
  end
  def self.run
    agent = C28.new 'trololo'
    puts "authenticates"  if agent.check 'trololo'
    puts "rejects"        unless agent.check 'no msg, just a smiley :)'
  end
end

class C29
  def self.make_padding(msg,offset=0)
    blen = (msg.size+offset) << 3
    msg = msg.force_encoding('ascii-8bit')
    msg += "\x80".force_encoding('ascii-8bit')
    msg += "\0".force_encoding('ascii-8bit') until ((msg.size+offset)&0x3f) == 56
    msg += [0,blen].pack("N2")
    return msg
  end
  def self.run
    otxt = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".force_encoding('ascii-8bit')
    fake = ';admin=true'.force_encoding 'ascii-8bit'
    agent = C28.new otxt
    intermediate = agent.digest.unpack("N5")
    256.times do |i|
      txt = make_padding(otxt,i)+fake
      nb = 64*((i + otxt.size)/64) + 64*((i+otxt.size)%64 == 0? 0: 1)
      digest = sha1(fake,intermediate,nb)
      puts 'yay' if agent.check(txt,digest)
    end
  end
end

class C30
  def initialize
    @key='a happy key'.force_encoding 'ascii-8bit'
  end
  def hash(msg)
    return md4(@key+msg)
  end
  def check(msg,thash)
    return md4(@key+msg) == thash
  end
  def self.make_padding(msg,offset=0)
    blen = (msg.size+offset) << 3
    msg = msg.force_encoding('ascii-8bit')
    msg += "\x80".force_encoding('ascii-8bit')
    msg += "\0".force_encoding('ascii-8bit') until ((msg.size+offset)&0x3f) == 56
    msg += [blen,0].pack("V2")
    return msg
  end
  def self.run
    agent = C30.new
    otxt = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".force_encoding('ascii-8bit')
    fake = ';admin=true'.force_encoding 'ascii-8bit'
    intermediate = agent.hash(otxt).unpack("V4")
    #256.times do |i|
      i = 'a happy key'.size
      txt = make_padding(otxt,i)+fake
      nb = 64*((i + otxt.size)/64) + 64*((i+otxt.size)%64 == 0? 0: 1)
      digest = md4(fake,intermediate,nb)
      puts 'yay' if agent.check(txt,digest)
    #end
  end
end

class C31
  #caguei
end
