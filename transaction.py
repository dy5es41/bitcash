#!/usr/bin/env python3
import os, random, base58, ecdsa, binascii, hashlib
import pyqrcode
from hexdump import hexdump
import socket, time, struct
from datetime import datetime

#lib convert address to cashAddr
from cashaddress import convert
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
	publ_key, publ_addr, WIF = privateKeyToPublicKey(private_key) return private_key,WIF, publ_key, publ_addr

#functions to send data to nodes
def make_message(command, payload):
	return struct.pack('<L12sL4s', MAGIC, command, len(payload), checksum(payload)) + payload

def get_version_message():
	version = 180002		#int32_t 4
	services = 1			#uint64_t 8
	timestamp = int(time.time())	#int64_t 8
	addr_recv = b'\x00'*26		#int64_t 26
	addr_from = b'\x00'*26		#int64_t 26
	nonce = random.getrandbits(64)	#uint64_t 8
	user_agent = b'\x00'		#int64_t ?
	start_height = 0		#int32_t 4

	#pack payload
	payload = struct.pack('<LQQ26s26sQsL', version, services, timestamp, addr_recv, addr_from,
		 nonce, user_agent, start_height)	
	return make_message(b'version', payload)

"""
construct a transaction that we can broadcasti
	#https://github.com/zeltsi/Mybitcoin/blob/master/tx%20as%20seen%20on%20youtube.py
		1. create a raw tx
		2. raw tx and sign that tx using the private key off addy1 to prove that I approve the transaction
		3. raw tx and signature in oder to create the real tx 
"""

def get_raw_tx_message():
	version  = struct.pack("<L",1)		#transaction data format version
	tx_in_count = struct.pack("<B", 1)	#index of transaction to spend

	#create previous output hash
	TX_OUT_USE = '2a6086fc4abd493ab068b77c7fa7b4e93fd055ff4b647c18e058af3e477453d3'
	
	#reverse BYTE ORDER, then, OG is in hex, thus we ahve to unhexlify and then rehex
	previous_output_hash = binascii.hexlify(binascii.unhexlify(TX_OUT_USE)[::-1]) #previous output hash
	
	#sourceIndex
	source_index = struct.pack('<L', 0) #
	
	

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

	get_raw_tx_message()

	exit(0)



	#socket/network
	#get the list of nodes that we can broadcast to
	nodes = list(socket.gethostbyname_ex('seed.bitcoinabc.org'))
	nodes = nodes[2] #filter

	#select a random node
	random.seed(datetime.now())
	node = random.choice(nodes) #singular node

	#get the message to send and dump it
	message = get_version_message() 
	hexdump(message)
	
	#connect to node
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.connect((node, 8333))
	
	#send message to node
	sock.send(message)
	hexdump(sock.recv(1024))
	
	
