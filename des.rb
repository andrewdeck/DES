#!/usr/bin/env ruby

# This is an implementation of the Data Encryption Standard
# as described by fips46-4.
# Author: Andrew Deck (techdeck)
#
# Note: Blocks are composed of bits numbered from left to right,
# 		i.e., the left most bit of a block is bit one.


LOWER_28 = 0xfffffff
UPPER_28 = LOWER_28 << 28
LOWER_32 = 0xffffffff
UPPER_32 = LOWER_32 << 32
STDOUT.sync = true

# The nonlinear set of S fucntions 1..8
S = [ [ [14,4,13,1,2,15,11,8,3,10,6,12,5,7,0,7],
        [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
        [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
        [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ],
      [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
        [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
        [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
        [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ],
      [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
        [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
        [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
        [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ],
      [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
        [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
        [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
        [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ],
      [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
        [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
        [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
        [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ],
      [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
        [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
        [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
        [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ],
      [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
        [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
        [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
        [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ],
      [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
        [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
        [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
        [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ] ]

IPerm = [ 58,50,42,34,26,18,10,2,
          60,52,44,36,28,20,12,4,
          62,54,46,38,30,22,14,6,
          64,56,48,40,32,24,16,8,
          57,49,41,33,25,17,9,1,
          59,51,43,35,27,19,11,3,
          61,53,45,37,29,21,13,5,
          63,55,47,39,31,23,15,7 ]

IPermInv = [ 40,8,48,16,56,24,64,32,
             39,7,47,15,55,23,63,31,
             38,6,46,14,54,22,62,30,
             37,5,45,13,53,21,61,29,
             36,4,44,12,52,20,60,28,
             35,3,43,11,51,19,59,27,
             34,2,42,10,50,18,58,26,
             33,1,41,9,49,17,57,25 ]

EPerm = [ 32,1,2,3,4,5,
          4,5,6,7,8,9,
          8,9,10,11,12,13,
          12,13,14,15,16,17,
          16,17,18,19,20,21,
          20,21,22,23,24,25,
          24,25,26,27,28,29,
          28,29,30,31,32,1 ]

PPerm = [ 16,7,20,21,
          29,12,28,17,
          1,15,23,26,
          5,18,31,10,
          2,8,24,14,
          32,27,3,9,
          19,13,30,6,
          22,11,4,25 ]
		 
PC1 = [ 57,49,41,33,25,17,9,
        1,58,50,42,34,26,18,
        10,11,3,60,52,44,36,
        63,55,47,39,31,23,15,
        19,11,3,60,52,44,36,
        7,62,54,46,37,30,22,
        14,6,61,53,45,37,29,
        21,13,5,28,20,12,4 ]
      
PC2 = [ 14,17,11,24,1,5,
        3,28,15,6,21,10,
        23,19,12,4,26,8,
        16,7,27,20,13,2,
        41,52,31,37,47,55,
        30,40,51,45,33,48,
        44,49,39,56,34,53,
        46,42,50,36,29,32 ]
      
LShifts = [ 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 ]

# Initial Permutation function as described on page 10 of fips46-3
# input: inblock, 64-bit block
# output: 64-bit block, permutated
def initial_permutation( inblock )
  outblock = 0
  for i in 1..64
    outblock += ((inblock & (1<<(64-i)))>>(IPerm[i-1]-i))
  end
  outblock
end

# Inverse Initial Permutation function
# input: block, 64-bit block
# output: 64-bit block, inversely-permutated
def inverse_initial_permutation( block )
  output = 0
  for i in 1..64
    output += ((block & (1<<(64-i)))>>(IPermInv[i-1]-i))
  end
  output
end

def permutated_choice_1( block )
  output = 0
  for i in 1..56
    output += ((block & (1<<(56-i)))>>(PC1[i-1]-i))
  end
  output
end

def permutated_choice_2( block )
  output = 0
  for i in 1..48
    output += ((block & (1<<(48-i)))>>(PC2[i-1]-i))
  end
  output
end

# takes in a 56-bit block, splits it into 2 halves, C & D
# then rotates the bits in C & D by shift bits.
def left_shift( block, shift )
  c = ( block & UPPER_28 ) >> 28
  d = block & LOWER_28
  c = (c >> (28-shift)) + ((c << shift) & LOWER_28)
  d = (d >> (28-shift)) + ((d << shift) & LOWER_28)
  result = (c << 28) + d
  result
end

# Populate array of Keys, 1 through 16
# only necessary to do this once.
#
def generate_key_schedule
  key = $key
  $KeySchedule = []
  key = permutated_choice_1(key)
  16.times do |i|
    key = left_shift(key, LShifts[i])
    $KeySchedule[i] = permutated_choice_2(key)
  end
end

# E function
# input: block, 32-bit block
# output: 48-bit block
def E( block )
  output = 0
  for i in 1..48
    output += (block & (1<<(32-EPerm[i-1])))>>(32-EPerm[i-1]-(48-i))
  end
  output
end

# S fuction described on page 14 of fips46-3.pdf
# input: sixb is the six bits to be permutated to 4 bits
#		 f is the number of the S function
def S( sixb, f)
  row=(sixb & 1)+((sixb & 32)>>4)
  col=(sixb>>1)&15
  S[f-1][row][col]
end

def P( l )
  result = 0
  for i in 1..32
    result += ((l & (1<<(32-i)))>>(PPerm[i-1]-i))
  end
  result
end

# f(R,K) 
# input: r is 32 bits
#		 k is a 48 bit key from the key schedule
def F( r, k )
  e = E(r)
  block = e ^ k
  bary = []
  for i in 1..8
    bary[i-1] = ((63 << ((8-i)*6)) & block) >> ((8-i)*6)
  end
  pary = []
  for i in 1..8
    pary[i-1] = S(bary[i-1],i)
  end
  result = 0
  for i in 1..8
    result += (pary[i-1] << (4-i))
  end
  result = P(result)
  result
end

def generate_new_key
  key_bytes = []
  8.times do |i|
    parity = 0
    byte = 0
    7.times do |j|
      bit = rand(2)
      parity = parity ^ bit
      byte += (bit << j)
    end
    #no bitwise not... o_O
    byte += (1 << 7) if parity == 0
    key_bytes[i] = byte
  end
  if $output_file.nil?
    $output_file = "private_key"
  end
  keyFile = File.new($output_file, "w+")
  keyFile.write key_bytes.pack("C*")
  keyFile.close
end

def valid_key?
  key = $key
  valid = true
  8.times do |i|
    byte = (key >> (i*8)) & 0xff
    parity = 0
    8.times do |j|
      parity = parity ^ ((byte >> j) % 2)
    end
    if parity == 0
      valid = false
    end
  end
  valid
end

def read_key
  key_bytes = []
  keyFile = File.new($key_file, "r")
  8.times do
    key_bytes.push(keyFile.getbyte)
  end
  keyFile.close
  $key = 0
  8.times do |i|
    $key += key_bytes[i] << (56 - (8*i))
  end
  $key
end

def read_file
  inFile = File.new($input_file, "r")
  $input_file_blocks = []
  byte_count = 0
  block = 0
  inFile.each_byte do |byte|
    block += byte << ((7 - (byte_count % 8)) * 8)
    byte_count += 1
    if byte_count % 8 == 0
      $input_file_blocks.push(block)
      block = 0
    end
  end
  if block != 0
    $input_file_blocks.push(block)
  end
  inFile.close
end

def encrypt
  generate_key_schedule
  read_file
  ########Progress Bar########
  print "|==================================================| 100%\n|"
  progress = 0
  progressCount = 0
  ########Progress Bar########
  $output_file_bytes = []
  $input_file_blocks.each do |block|
    block = initial_permutation(block)
    right = block & LOWER_32
    left = (block & UPPER_32) >> 32
    16.times do |i|
      left_prime = right
      right_prime = left ^ F(right, $KeySchedule[i])
      left = left_prime
      right = right_prime
    end
    block = (right << 32) + left
    block = inverse_initial_permutation(block)
    8.times do |i|
      byte = ( block >> (8 * (7-i))) & 0xff
      $output_file_bytes.push(byte)
    end
    ########Progress Bar########
    progressCount += 1
    position = 50.0 * progressCount / $input_file_blocks.size
    diff = position.floor - progress
    if diff > 0
      diff.times { print "=" }
      progress = position.floor
    end
    ########Progress Bar########
  end
  outFile = File.new("#{$input_file}.des", "w+")
  outFile.write  $output_file_bytes.pack("C*")
  outFile.close
  ########Progress Bar########
  print "| DONE\n"
  ########Progress Bar########
end

def decrypt
  generate_key_schedule
  read_file
  ########Progress Bar########
  print "|==================================================| 100%\n|"
  progress = 0
  progressCount = 0
  ########Progress Bar########
  $output_file_bytes = []
  $input_file_blocks.each do |block|
    block = initial_permutation(block)
    right = block & LOWER_32
    left = (block & UPPER_32) >> 32
    15.downto(0) do |i|
      left_prime = right
      right_prime = left ^ F(right, $KeySchedule[i])
      left = left_prime
      right = right_prime
    end
    block = (right << 32) + left
    block = inverse_initial_permutation(block)
    8.times do |i|
      byte = ( block >> (8 * (7-i))) & 0xff
      $output_file_bytes.push(byte)
    end
    ########Progress Bar########
    progressCount += 1
    position = 50.0 * progressCount / $input_file_blocks.size
    diff = position.floor - progress
    if diff > 0
      diff.times { print "=" }
      progress = position.floor
    end
    ########Progress Bar########
  end
  #remove null bytes at the end of the file (byproduct of the intial padding)
  7.times do
    if $output_file_bytes[-1] == 0
      $output_file_bytes.pop
    end
  end
  if File.extname($input_file) == ".des"
    outputFileName = $input_file[0..-5]
  else
    outputFileName = "#{$input_file}.decrypt"
  end
  outFile = File.new(outputFileName, "w+")
  outFile.write $output_file_bytes.pack("C*")
  outFile.close
  ########Progress Bar########
  print "| DONE\n"
  ########Progress Bar########
end

def show_usage
  puts "Usage: ./des.rb -e <file to encrypt> -k <key{file}>"
  puts "       ./des.rb -d <file to decrypt> -k <key{file}>"
  puts "        for more options ./des.rb -h\n\n"
end

def show_detailed_usage
  puts "\n Options:"
  puts "    -e, --encrypt <filename>  Encrypt <filename>, requires -k\n"
  puts "    -d, --decrypt <filename>  Decrypy <filename>, requires -k\n"
  puts "    -k, --key <filename>      Specifies the DES key to be used\n\n"
  puts "    --keygen <filename>       Will generate a pseudo-random DES key and"
  puts "                              store it in <filename>\n"
end

if ARGV[0] == '-h' || ARGV[0] == '--help'
  show_detailed_usage
else
  0.upto(ARGV.length - 1) do |i|
    case ARGV[i]
      when "-e", "--encrypt"
        $encrypt = true
        $input_file = ARGV[i+1]
      when "-d", "--decrypt"
        $decrypt = true
        $input_file = ARGV[i+1]
      when "-k", "--key"
        $key_file = ARGV[i+1]
      when "--keygen"
        $keygen = true
        $output_file = ARGV[i+1]
    end
  end
  
  if $encrypt == true
    if !$input_file.nil? && File.file?($input_file)
      if !$key_file.nil?
        read_key
        if valid_key?
          encrypt
        else
          puts "Key is invalid."
        end
      else
        puts "You need to provide a key file."
      end
    else
      puts "You need to provide a file to encrypt."
    end
  elsif $decrypt == true
    if !$input_file.nil? && File.file?($input_file)
      if !$key_file.nil?
        read_key
        if valid_key?
          decrypt
        else
          puts "Key is invalid."
        end
      else
        puts "You need to provide a key file."
      end
    else
      puts "You need to provide a file to decrypt."
    end
  elsif $keygen == true
    generate_new_key
  else
    show_usage
  end
end
