#!/usr/bin/env python3
import os, random, base58, ecdsa, binascii, hashlib
import pyqrcode
from hexdump import hexdump
import socket, time, struct
from datetime import datetime

#homebrew class
from address import address as Address
#constant
random.seed(501971)
MAGIC = 0xe8f3e1e3


#helper function(s)
def str2hex(x):
	return binascii.hexlify(x).decode()

def dbl256(x):
	return hashlib.sha256(hashlib.sha256(x).digest()).digest()

def checksum(x):
	return dbl256(x)[:4]

def b58wchecksum(x):
	return base58.b58encode(x+checksum(x))

#thanks gh
def ripemd160(x):
	d = hashlib.new('ripemd160')
	d.update(x)
	return d

def privateKeyToPublicKey(s):
	
	
	key = binascii.unhexlify(s) #hex as bytes
	
	#ecdsa
	sk = ecdsa.SigningKey.from_string(key, curve=ecdsa.SECP256k1)
	vk = sk.verifying_key
	
	#prefix of 04 for bcash addy
	publ_key = b"\x04" + vk.to_string()
	hash160 = ripemd160(hashlib.sha256(publ_key).digest()).digest()
	
	publ_addr = b58wchecksum(b"\x00" + hash160)
	publ_addr = publ_addr.decode('utf-8')
	
	WIF = b58wchecksum(b"\x80" + binascii.unhexlify(s))
	WIF = WIF.decode() #convert 2 str
	
	#byte string to hex on public key, output format
	publ_key = str2hex(publ_key)
	return publ_key, publ_addr, WIF

def seededprivate_generatepublic(seed):
	random.seed(seed)
	private_key = ''.join(['%x' % random.randrange(16) for x in range(0, 64)])
	publ_key, publ_addr, WIF = privateKeyToPublicKey(private_key)
	return private_key,WIF, publ_key, publ_addr

#functions to send data to nodes
def make_message(command, payload):
	return struct.pack('<L12sL4s', MAGIC, command, len(payload), checksum(payload)) + payload

def getVersionMsg():
  version = 180002
  services = 1
  timestamp = int(time.time())
  addr_me = b"\x00"*26
  addr_you = b"\x00"*26
  nonce = random.getrandbits(64)
  sub_version_num = b"\x00"
  start_height = 0

  payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_me,
      addr_you, nonce, sub_version_num, start_height)
  return make_message(b'version', payload)


def get_version_message():
	version = 180002			 	#int32_t 4
	services = 1 					#uint64_t 8
	timestamp = int(time.time()) 	#int64_t 8
	addr_recv = b'\x00'*26 			#int64_t 26
	addr_from = b'\x00'*26 			#int64_t 26
	nonce = random.getrandbits(64) 	#uint64_t 8
	user_agent = b'\x00' 			#int64_t ?
	start_height = 0				#int32_t 4

	#pack payload
	payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_recv, addr_from,
		 nonce, user_agent, start_height)	
	return make_message(b'version', payload)

if __name__ == '__main__':
	#address1, note splat
	address1 = Address('address1',*seededprivate_generatepublic(501971))
	address1.print()
	address1.qrcode()
	
	print('\n')

	#address2
	address2 = Address('address2',*seededprivate_generatepublic(9128060))
	address2.print()
	address2.qrcode()

	print('GOAL: {} -> {}'.format(address1.address, address2.address))	

	#socket/network
	#get the list of nodes that we can broadcast to
	nodes = list(socket.gethostbyname_ex('seed.bitcoinabc.org'))
	nodes = nodes[2] #filter

	#select a random node
	random.seed(datetime.now())
	node = random.choice(nodes) #singular node
	gvm = get_version_message()
	
	###SENT
	hexdump(gvm)
	###


	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((node, 8333))
	sock.send(gvm)
	
	###RECV
	hexdump(sock.recv(2048))
	###
