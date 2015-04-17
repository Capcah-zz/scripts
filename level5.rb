require 'base64'
require 'openssl'
require 'set'
require 'net/http'
require './level3'
require 'stringio'

NIST = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

def randint
 return OpenSSL::Random.random_bytes(128).unpack("H*")[0].to_i 16 
end

class Integer
  def strf
    return strfy(self)
  end
end

class String
  def nfy
    return self.unpack("H*")[0].to_i(16)
  end
end

def num_digest(str)
  return OpenSSL::Digest::SHA256.new.hexdigest(str).nfy
end

def mexp(e,b,p=NIST)
  return (b**e)%p if e <16
  a = mexp(e/2,b,p)
  return (a*a*(e&1 == 1 ? b : 1))%p
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
  raise unless (t-og**3) == 0
  og
end

def strfy(i)
  a   = i
  acc = []
  while a != 0
    acc << (a&0xff)
    a   >>= 8
  end
  return acc.reverse.map(&:chr).join
end

class C33
  attr_accessor :skey,:pkey,:p,:str_sec
  def initialize
    @g = 2
    @p = NIST
    gen_pair
  end

  def gen_pair
    agent = OpenSSL::Cipher.new 'AES-128-CBC'
    @skey = agent.random_key.unpack("C*").reduce{|acc,x| (acc<<8)+x}
    @pkey = modexp(@skey)
  end
  
  def calc_secret(ext_key)
    @sec = modexp(@skey,ext_key)
    @str_sec = strfy(@sec)
  end

  def send_msg(msg)
    d_agent = OpenSSL::Digest.new 'SHA1'
    key = d_agent.digest(@str_sec)
    c_agent = OpenSSL::Cipher.new 'AES-128-CBC'
    c_agent.encrypt
    c_agent.key = key
    iv = c_agent.random_iv
    ctx = c_agent.update(msg)
    ctx << c_agent.final
    return ctx + iv
  end

  def receive_msg(ctx)
    d_agent = OpenSSL::Digest.new 'SHA1'
    key = d_agent.digest(@str_sec)
    c_agent = OpenSSL::Cipher.new 'AES-128-CBC'
    c_agent.decrypt
    c_agent.key = key
    c_agent.iv = ctx[-16..-1]
    begin
      msg = c_agent.update ctx[0...-16]
      msg << c_agent.final
    rescue
      msg = nil
    end
    return msg
  end

  def gen_all
    agent = OpenSSL::Cipher.new 'AES-128-ECB'
    @a = agent.random_key.unpack("C*").reduce{|acc,x| (acc<<8)+x}
    @b = agent.random_key.unpack("C*").reduce{|acc,x| (acc<<8)+x}
    @A, @B = modexp(@a), modexp(@b)
  end

  def check_keys
    c1 = modexp(@b,@A)
    c2 = modexp(@a,@B)
    puts 'keys consistent' if c1 == c2
  end

  def pkeys
    return [@a,@b]
  end

  def skeys
    return [@A,@B]
  end

  def modexp(e,b=@g)
    return mexp(e,b,@g)
  end

  def self.run
    c = C33.new
    c.gen_all
    c.check_keys
  end
end

class C34
  def self.run
    adm = C33.new
    bob = C33.new
    eve = C33.new
    #first round
    wire = adm.pkey
    #eve
    wire = adm.p
    bob.calc_secret(wire)
    #second round
    wire = bob.pkey
    #eve
    wire = bob.p
    adm.calc_secret(wire)
    #third round
    wire = adm.send_msg('hello bob!')
    #bob checks its message
    puts 'bob is ok' if bob.receive_msg(wire)== "hello bob!"
    eve.str_sec = ''
    puts "and eve has the message: #{eve.receive_msg(wire)}"
  end
end

class C35
  def self.run
    # g=1 eve.sec = '1', 1^y = 1
    # g=p eve.sec = '' , p`mod`p = 0, 0^y = 0
    # g=p-1 eve.sec = '1'. p-1`mod`p = (-1)`mod`p, eve can guess @sec = {1,p-1}
  end
end

class Server_SRP
  def initialize(id,password)
    @id = id
    @g = 2
    @k = 3
    @salt = OpenSSL::Random.random_bytes 1024
    @x = num_digest(@salt+password)
    @v = mexp(@x,@g)
  end
  def first_ans(f_msg)
    @b = randint
    @B = (mexp(@b,@g) + @k*@v)%NIST
    @A = f_msg[1]
    @u = num_digest(strfy(@A)+strfy(@B))
    return [@salt,@B]
  end
  def snd_ans(s_msg)
    @s = mexp(@b,@A*mexp(@u,@v))
    @K = OpenSSL::Digest::SHA256.hexdigest(strfy(@s))
    return @K == s_msg
  end
end

class Client_SRP
  attr_accessor :a,:A
  def initialize(id,password)
    @g = 2
    @k = 3
    @id = id
    @password = password
  end
  def prepare_auth 
    @a = randint
    @A = mexp(@a,@g)
    return [@id,@A]
  end

  def start_auth(response)
    @salt, @B = response
    @u = num_digest(strfy(@A)+strfy(@B))
    @x = num_digest(@salt+@password)
    @s = mexp(@a+@u*@x,@B-@k*mexp(@x,@g))
    @K = OpenSSL::Digest::SHA256.new.hexdigest(strfy(@s))
    return @K
  end
end

class C36
  def self.run
    client = Client_SRP.new('jinx','ibombulol')
    server = Server_SRP.new('jinx','ibombulol')
    wire = client.prepare_auth
    wire = server.first_ans(wire)
    wire = client.start_auth(wire)
    puts 'OK' if server.snd_ans(wire)
  end
end

def invmod(a,b)
  def extended_gcd(a,b)
    last_remainder, remainder = a.abs, b.abs
    x, last_x, y, last_y = 0, 1, 1, 0
    while remainder != 0
      last_remainder, (quotient, remainder) = remainder, last_remainder.divmod(remainder)
      x, last_x = last_x - quotient*x, x
      y, last_y = last_y - quotient*y, y
    end
   
    return last_remainder, last_x * (a < 0 ? -1 : 1)
  end
  g,x = extended_gcd(a, b)
  puts 'broken math' if ((x%b)*a)%b != 1
  return x%b
end

class SimpleClient
  def initialize(usr,pass)
    @usr = usr
    @pass = pass
    @g = 2
    @a = randint
  end
  def handshake
    @A = mexp(@a,@g)
    return @A
  end
  def auth(msg)
    @salt,@B,@u = msg
    @x = num_digest(@salt+@pass)
    @S = mexp(@a+@u*@x,@B)
    @K = OpenSSL::Digest::SHA256.new.hexdigest(strfy(@S))
    return @K
  end
end

class SimpleServer
  def initialize(usr,pass)
    @salt = OpenSSL::Random.random_bytes 1024
    @g = 2
    @x = num_digest(@salt+pass)
    @v = mexp(@x,@g)
    @b = randint
  end
  def handshake(msg)
    @A = msg
    @B = mexp(@b,@g)
    @u = randint
    return [@salt,@B,@u]
  end
  def auth(msg)
    @S = mexp(@b,@A*mexp(@u,@v))
    @K = OpenSSL::Digest::SHA256.new.hexdigest(strfy(@S))
    return @K == msg
  end
end

class C37
  def self.run
    server = Server_SRP.new('jinx','ibombulol')
    server.first_ans(['jinx',0])
    prediction = OpenSSL::Digest::SHA256.new.hexdigest(strfy(0))
    puts 'broke with N=0' if server.snd_ans(prediction)
    server = Server_SRP.new('jinx','ibombulol')
    server.first_ans(['jinx',NIST])
    puts 'broke with N=p' if server.snd_ans(prediction)
  end
end

class C38
  def self.run
    words = File.new('/etc/dictionaries-common/words').read.split("\n")
    password = words.sample
    puts "secret is #{password}"
    client = SimpleClient.new('jinx',password)
    server = SimpleServer.new('jinx',password)
    #since g=2, B=4 => b=2
    _b,_B = 2,4
    _A = client.handshake
    _s = (_A*_A)%NIST
    _K = client.auth(['',_B,1])
    words.each do |word|
      _x = num_digest(word)
      _S = (_s*mexp(_x,_B))%NIST
      puts word if _K == OpenSSL::Digest::SHA256.hexdigest(strfy(_S))
    end
  end
end

class C39
  attr_accessor :pkey
  def initialize
    @p = OpenSSL::BN::generate_prime(1024).to_i
    @q = OpenSSL::BN::generate_prime(1024).to_i
    @n = @p*@q
    @et = (@p-1)*(@q-1)
    @e = 3
    @d = invmod(@e,@et)
    @pkey = [@e,@n]
    @skey = [@d,@n]
  end
  def encrypt(m)
    return mexp(@e,m.nfy,@n)
  end
  def decrypt(c)
    return mexp(@d,c    ,@n).strf
  end
  def self.run
    agent = C39.new
    msg = agent.encrypt('hey there nubs')
    puts agent.decrypt(msg)
  end
end

class C40
  def self.run
    as = [C39.new,C39.new,C39.new]
    ns = as.map{|agent| agent.pkey[1]}
    ms = (0...ns.size).map{|i| ns[(i+1)%ns.size]*ns[(i+2)%ns.size]}
    cs = as.map{|agent| agent.encrypt 'hello, I am a happy penguin and you can\'t catch me'}
    result = (0...cs.size).map{|i| cs[i]*ms[i]*invmod(ms[i],ns[i])}.inject(0){|acc,x| acc+x}
    #puts result
    _N = ns.inject(1){|acc,x| acc*x}
    result = result% _N
    while true
      begin
        puts bcube(result).strf
        break
      rescue
        result += _N
      end
    end
  end
end

RSA = C39
