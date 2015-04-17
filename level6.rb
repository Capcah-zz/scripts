require 'base64'
require 'openssl'
require 'set'
require 'net/http'
require './level5'
require 'stringio'

class Array
  def group(n)
    (0...self.size/n).map{|i| self[n*i...n*(i+1)] }
  end
end

P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
G =  0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

class C41
  def self.run
    agent = C39.new
    c = agent.encrypt('a really secret message, hohoho')
    e, n = agent.pkey
    s = randint
    c_ = (c*mexp(e,s,n))%n
    scrambled = agent.decrypt c_
    puts (scrambled.nfy*invmod(s,n)%n).strf
  end
end

class String
  def ascii
    self.force_encoding 'ascii-8bit'
  end
end

#signing and checking operations
class C39
  def sign(msg)
    bmsg = "\x00\x01"+"\xff".ascii*(msg.size-4)+"\x00"+
            OpenSSL::Digest::SHA256.digest(msg)
    [msg,decrypt(bmsg.nfy)]
  end
  def check(msg,sig)
    bmsg = "\x01"+"\xff".ascii*(msg.size-4)+"\x00"+
            OpenSSL::Digest::SHA256.digest(msg)
    a = encrypt(sig).strf
    return a.index bmsg
  end
end

def bcube(t,fg=0,og=0)
  step = 1
  a = step**3
  while a < t
    step <<= 1
    a = step**3
  end
  step /= 2
  og = step
  fg = step*2
  #root has to be in [og,fg]
  while step > 0
    a = (og+step/2)**3
    if a == t
      og += step/2
      break
    elsif a < t
      og = og+step/2
    else
      fg = fg-step/2
    end
    step = step/2
  end
  [og,fg]
end

class C42
  def self.run
    c = C39.new
    msg,sig = c.sign 'a check for the test'
    puts 'signs ok' if c.check(msg,sig)
    fake = 'hi mom'
    head = ("\x01"+"\xff".ascii*(fake.size-4)+"\x00"+
            OpenSSL::Digest::SHA256.digest(fake)+ "\x00".ascii*100).nfy
    sig = bcube(head)
    puts 'faked signature' if c.check(fake,sig[1].strf)
  end
end

class DSA
  attr_accessor :pubkey
  def initialize(g=nil)
    @p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    @q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    @g = g || 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    @x = randint % @q
    @y = mexp(@x,@g,@p)
    @pubkey = [@p,@q,@g,@y]
  end
  def sign(m)
    @k = randint
    r = mexp(@k,@g,@p)% @q
    h = num_digest(m)
    s = (invmod(@k,@q)*(h+@x*r))% @q
    return sign(m) if r == 0 || s == 0
    return [r,s]
  end
  def check(m,sgn)
    r,s = sgn
    return false if r == 0 || r > @q || s == 0 || s > @q
    w  = invmod(s,@q)
    u1 = (num_digest(m)*w)% @q
    u2 = (r*w)% @q
    v  = ((mexp(u1,@g,@p)*mexp(u2,@y,@p))% @p)% @q
    return v == r
  end
  def break(m,sgn)
    r,s = sgn
    #@x is not touched in this function
    x = (((@k*s)-num_digest(m))*invmod(r,@q))% @q
    puts 'broken with k and q' if x == @x
  end
end

class C43
  def self.crack
    val = 0xd2d0714f014a9784047eaeccf956520045c45265
    r = 548099063082341131477253921760299949438196259240
    s = 857042759984254168557880549501802188789837994940
    y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
    g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
    p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
    x= 0
    65536.times do |i|
      x = (((i*s)-val)*invmod(r,q))%q
      break if mexp(x,g,p) == y
    end
    puts "your key is #{x}, motherfucker" if mexp(x,g,p) == y
  end
  def self.run
    agent = DSA.new 
    msg = 'message to be signed'
    sig = agent.sign msg
    puts 'signature ok' if agent.check(msg,sig)
    agent.break(msg,sig)
    crack
    end
end

class C44
  def self.run
    y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    data = Net::HTTP.get(URI('http://cryptopals.com/static/challenge-data/44.txt')
            ).split(/msg: |s: |r: |m: |\n/).reject(&:empty?).group(4)
    x = 0
    data.zip([data]*data.size).each do |d2,dv|
      dv.each do |d1|
        if d1[1].nfy < d2[1].nfy
          d1,d2 = [d2,d1]
        end
        msg1,s1,r1,m1 = d1
        msg2,s2,r2,m2 = d2
        next unless r1 == r2 && s1 != s2
        s1,s2 = [s1,s2].map{|x| x.to_i 10}
        m1,m2 = [m1,m2].map{|x| x.to_i 16}
        r1 = r1.to_i 10
        inv_ds = invmod(s2-s1,Q)
        dH = (num_digest(m2.strf)-num_digest(m1.strf))%Q
        k = (inv_ds * dH)%Q
        x = (invmod(r1,Q)*(s1*k - num_digest(m1.strf)))%Q
      end
    end
    raise if x == 0
    puts OpenSSL::Digest::SHA1.hexdigest(x.strf.unpack("H*")[0])
  end
end 

class C45
  def self.run
    #mimimi
  end
end

class RSA
  def leak(ctx)
    return decrypt(ctx).nfy&1
  end
end

class C46
  def self.run
    rsa = RSA.new
    chal = Base64.decode64('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
    ctx = rsa.encrypt(chal)
    ans = 0
    i,factor = 0,rsa.pkey[1]/2
    while factor != 0
      ctx = (ctx*8)
      ans += rsa.leak(ctx)*factor
      factor /= 2
    end
    puts ans.strf
  end
end

class C47
end
