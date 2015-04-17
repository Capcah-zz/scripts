require 'base64'
require 'openssl'
require 'set'
require 'net/http'

def xor(s1,s2)
  s1.zip(s2).map{ |x,y| !x ?y:!y ?x:x^y }
end

class C17
  def encrypt 
    chall = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
      "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
      "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
      "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
      "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
      "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
      "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
      "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
      "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
      "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
      ]
    agent = OpenSSL::Cipher.new 'AES-128-CBC'
    agent.encrypt
    @key = agent.random_key
    iv = agent.random_iv
    chall.map! do |s|
      dec = Base64.decode64 s
      sd = (sd = -dec.size%16).zero? ? 16 : sd
      (dec + ([sd]*sd).pack('C*'))
    end
    return [agent.update(chall.sample)+agent.final,iv]
  end

  def decrypt(cyphertext,iv)
    agent = OpenSSL::Cipher.new 'AES-128-CBC'
    agent.decrypt
    agent.key = @key
    agent.iv = iv
    begin
      res = agent.update(cyphertext) + agent.final
      #len = res[-1].unpack('C')[0]
      #return res[-len..-1].unpack('C*').select{|x| x == len}.size == len
      return true
    rescue
      return false
    end
  end

  def attack(cyphertext,iv)
    def break_block(cblock,oiv)
      iv = [0]*16
      ans = []
      (1..16).each do |j|
        256.times do |i|
          iv[16-j] = i
          break if decrypt(cblock,iv.pack("C*"))
        end
        ans << (iv[16-j])
        iv.map!{|x| x^j^(j%16+1)}
      end
      iv.map!{|x| x^1}
      return xor(iv,oiv.unpack("C*")).select{|s| s > 16}.pack("C*")
    end
    ret = ""
    (cyphertext.size/16).times do |i|
      cb = cyphertext[16*i...16*(i+1)]
      ret += break_block(cb,iv)
      iv = cb
    end
    return ret
  end

  def self.test
    a = C17.new
    ctxt,iv = a.encrypt
    a.decrypt(ctxt,iv)
  end

  def self.run
    a = C17.new
    puts (1..100).map{|i| a.attack(*a.encrypt)}.sort.uniq.select{|s| !s.index /[^ -~]/}
  end
end

class C18
  def self.itol(i)
    res = []
    8.times do |j|
      res << (i&0xff)
      i >>= 8
    end
    return [0]*8+res
  end

  def self.ltoi(l)
    i,ctr =0,0
    l[8...16].each do |b|
      i += b<<ctr
      ctr += 8
    end
    return i
  end

  def self.gstream(nonce,key,len)
    agent = OpenSSL::Cipher.new 'AES-128-ECB'
    agent.encrypt
    agent.key = key
    stream = []
    (len+1).times do |i|
      #since enonce is always 16 bytes, we don't need to worry about padding
      stream << agent.update(itol(nonce).pack("C*"))
      nonce += 1
    end
    stream << agent.final
    return stream.join.unpack("C*")
  end

  def self.encrypt(ptx,key,nonce)
    return xor(ptx.unpack("C*"),gstream(nonce,key,ptx.size/16))[0...ptx.size].pack("C*")
  end

  def self.decrypt(ctx,key,nonce)
    return xor(ctx.unpack("C*"),gstream(nonce,key,ctx.size/16))[0...ctx.size].pack("C*")
  end

  def self.test
    puts ltoi(itol(12345678901234567890))
    ptx = Base64.decode64('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    key = "YELLOW SUBMARINE"
    puts decrypt(ptx,key,0)
  end

  def self.run
    puts "This module does not need to run, it only implements AES-CTR"
  end
end

class C19
  def self.xmap(bundle)
    s1,arry = bundle
    if s1.is_a? Enumerable
      [s1,arry.map{|s2| xor(s1,s2)[0...[s1.size,s2.size].min]}]
    else
      [s1,arry.map{|s2| s1^s2 }]
    end
  end

  def self.tag_characters(ctxs,prnt)
    xor_table = prnt.zip([prnt]*prnt.size).map(&method(:xmap)).map{|c,s| [c,Set.new(s)]} 
    ctxs.zip([ctxs]*ctxs.size).map(&method(:xmap)).map do |line,xorred|
      sline =  Set.new line
      sets = (1..xorred.map(&:size).max).map{|x| Set.new}
      xorred.each do |xor_line|
        sets[0...xor_line.size].zip(xor_line).each{|set,char| set << char}
      end
      sets.map do |set|
        xor_table.select{|c,line| set.subset? line}.map(&:first)
      end
    end
  end

  def self.run(first_run=nil)
    challenge= [
     "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
     "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
     "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
     "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
     "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
     "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
     "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
     "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
     "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
     "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
     "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
     "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
     "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
     "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
     "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
     "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
     "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
     "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
     "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
     "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
     "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
     "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
     "U2hlIHJvZGUgdG8gaGFycmllcnM/",
     "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
     "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
     "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
     "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
     "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
     "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
     "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
     "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
     "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
     "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
     "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
     "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
     "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
     "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
     "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
     "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
     "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
    ].map{|s| Base64.decode64(s)}.map do |t|
      #Let's suppose we don't know either the nonce nor the key.
      C18.encrypt(t,"YELLOW SUBMARINE",1234567890).unpack("C*")
    end
    prnt = ('a'.ord..'z'.ord).to_a+('A'.ord..'Z'.ord).to_a+
      [' ','.',',','?',';',':','-',"'",'"','/','!'].map(&:ord)
    #Run this code first to get the partial guesses of the plain text strings
    tag_characters(challenge,prnt).each_with_index do |s1,i|
      puts "#{i}=> #{s1.map{ |s2|
        chr = s2.map(&:chr).min
        chr ? chr : '-'
      }.join}"
    end
    #Get the biggest/best of them and resstore the original string to xor the
    #others.
    phrase = "He, too, has been changed in his".unpack "C*"
    puts challenge.map{|s| xor(xor(challenge[-3][0...s.size],s),phrase[0...s.size]).map(&:chr).join}
  end
end

class C20
  def self.run
    letters = Set.new
    ctxs = Net::HTTP.get(URI 'https://gist.githubusercontent.com/tqbf/3336141/raw/d601f0b675feef570188ab2c8f347843f965ee14/gistfile1.txt').split("\n").map{|x| Base64.decode64 x}.each{|x| x.each_char{|y| letters << y}}.map do |t|
      C18.encrypt(t,"YELLOW SUBMARINE",1234567890).unpack("C*")
    end
    puts letters.to_a.sort.inspect
    minl = ctxs.map(&:size).min
    ctxs.map!{|x| x[0...minl]}
    C19.tag_characters(ctxs,letters.to_a.map(&:ord)).each_with_index do |s1,i|
      puts "#{i}=> #{s1.map{ |s2|
        chr = s2.map(&:chr).min
        chr ? chr : '-'
      }.join}"
    end 
  end
end

class MT
  attr_accessor :mt
  def initialize(seed)
    @N,@M,@A,@UMASK,@LMASK=624,397,0x9908b0df,0x80000000,0x7fffffff
    @TMASKB,@TMASKC = 0x9d2c5680,0xefc60000
    @mt = [0]*@N
    @N.times do |i|
      @mt[i] = seed & 0xffff0000
      seed = 69069 * seed + 1
      @mt[i] |= (seed & 0xffff0000) >> 16
      seed = 69069 * seed + 1
    end
    @index = 0
  end

  def rand
    gnum if @index == 0
    y = @mt[@index]
    y ^= (y >> 11)
    y ^= (y << 7)&@TMASKB
    y ^= (y << 15)&@TMASKC
    y ^= (y >> 18)
    @index = (@index+1)% @N
    return y
  end

  def gnum
    @N.times do |i|
      y = (@UMASK & @mt[i])|(@mt[(i+1)% @N] & @LMASK)
      @mt[i] = (@mt[(i+@M)% @N] ^ (y>>1) ^ ((y&1 != 0)?@A:0))
    end
  end
end

class C21
  def self.run
    rg = MT.new 3457
  end
end

class C22
  def self.run
    require 'time'
    #getting the number of seconds, sucks to wait
    offset = rand(1000)
    puts "The hidden generator runned at #{offset} seconds"
    first_number = MT.new(Time.at(Time.now+offset).to_i).rand
    max_time = Time.now+1040 #Suppose I have waited 1040 seconds to start running my stuff
    1400.times do |i|
      if MT.new(Time.at(max_time-i).to_i).rand == first_number
        puts "The hidden generator runned #{i} seconds before, i+offset = #{i+offset}"
        return
      end
    end
  end
end

class C23
#  def self.rev_op(num,nshift,const,reversed=nil)
#    step = num.size/nshift
#    def sh(x,times=1)
#      sh = lambda{|x| (reversed) ? x >> nshift*times : x << nshift*times}
#    end
#    leaked = num&sh(
#  end
  def self.reverse(rnum)
    #step 4
    prev =  ((rnum >> 18 )^rnum)
    #step 3
    med_leak = prev^((prev<<15)&0xefc60000&0x3fffffff)
    prev = (((med_leak<<15)&0xefc60000)^prev)
    #step 2
    leaked = prev&0x7f
    (1..4).each do |i|
      leaked |= ((leaked<<7)&0x9d2c5680^prev)&(0x7f<<7*i)
    end
    prev = leaked
    #step 1
    leaked = prev&(0x7ff<<21)
#    leaked = [prev>>22]
    (1..2).each do |i|
#      leaked << ((((leaked.reverse.inject(0){|a,e|(a>>11)|e}>>11)^prev) >> (11*i))&0x7ff)
      leaked |= ((leaked>>11)^prev)&(0x7ff<<(21-11*i))
    end
#    rsteps << leaked.reverse.inject(0){|a,e|(a<<11)|e}
    return leaked
  end

  def self.crack(gen)
    state = (0...624).map{|i| reverse gen.rand}
    faker = MT.new 0
    faker.mt = state
    puts "Got from gen: #{gen.rand} and from faker: #{faker.rand}"
  end

  def self.run
    gen = MT.new 47474747
    crack(gen)
  end
end

class C24
  attr_accessor :key
  def mt_crypt(msg)
    gen = MT.new @key
    keystream = (0..msg.size/4).map{|i| gen.rand}.map{|x| [3,2,1,0].map{|l| (x>>l)&0xff}}.flatten[0...msg.size]
    return xor(msg,keystream)
  end

  def initialize(key=nil)
    @key = key ? key : rand((1<<16)-1)
  end

  def self.test
    c = C24.new
    puts c.mt_crypt(c.mt_crypt('hai guys, how are you doing so far?'.unpack("C*"))).pack("C*")
  end

  def self.password_tester(password)
    #assuming that the keys are still 16 bits
    ((1<<16)-1).times do |i|
      c = C24.new i
      v = c.mt_crypt(password)
      #considering it's unlikely to another key to  decrypt to printables
      unless v =~ /[^ -~]/
        puts "password was generated with MT19934, with value #{v}"
      end
    end
  end

  def self.run
    message = ('A'*14).unpack("C*")
    cryptor = C24.new
    ctx = cryptor.mt_crypt(message)
    # if you do not wish to wait, pass a small number as the parametr here
    si = cryptor.key
    puts "Starting the process to guess the key, my code is slow, be patient"
    ((1<<16)-1).times do |i|
      c = C24.new i
      if c.mt_crypt(message) == ctx
        puts "Got #{i} for saved key #{si}"
        break
      end
    end
  end
end

#[C17,C19,C20,C21,C22,C23,C24].each do |m|
#  puts "=> Runing #{m.inspect}"
#  m.run
#end
