import elliptic_curves, encryption
import socket, select, binascii, socketserver, sys, threading, _thread, secrets, argparse
from rich import print

PORT = 7777
p_lock = threading.Lock()
username = ''
password = ''

def print_with_lock(p):
	p_lock.acquire()
	if type(p) == tuple:
		for i in p:
			print(i, end= " ")
		print()
	else: print(p)
	p_lock.release()

class Ecsrp_server():
	def __init__(self, addr: tuple, username: str, password: str, verbose: bool) -> None:
		self.verbose = verbose
		self.username = username
		self.password = password
		self.salt = secrets.token_bytes(0x10)
		self.conn_addr = addr
		self.stage = 0
		self.w = elliptic_curves.WCurve()
		self.x_w_a = b''
		self.x_w_a_parity = -1
		self.s_b = b''
		self.x_w_b = b''
		self.x_w_b_parity = -1
		self.h = b''
		self.z_input = b''
		self.z = b''
		self.client_z = b''
		self.server_cc = b''
		self.i = b''
		self.gamma = None
		self.msg = b''
		self.resp = b''

	# handles requests based on the handshake stage 
	def process_msg(self):
		self.msg = b''
		if self.resp == b'': return 0
		if self.stage == 0: # initial handshake message from client 
			return self.public_key_exchange()
		elif self.stage == 1: # client confirmation code 
			if len(self.resp) != 0x20:
				print_with_lock("[red][-] Error: invalid client confirmation code length[/red]")
				return -1
			self.client_cc = self.resp
			if self.verbose: 
				print("[*] Receiving data")
				print("    [*] Received confirmation code " + binascii.hexlify(self.client_cc).decode())
			return self.gen_shared_secret()
		elif self.stage == 2:
			print_with_lock("[*] Authentication complete, terminating")
			exit(0)

	# performs ECPEPKGP-SRP-B to generate a password-entangled public key
	def gen_server_public_key(self) -> None:
		self.gamma, self.gamma_parity, self.i = self.w.ecpvdgp_srp(self.username,
			self.password, self.salt)

		if self.verbose: print("    [*] Calling ECPEPKGP-SRP-B")
		w_b = self.w.ecpepkgp_srp_b(self.s_b, self.w.to_binary(self.gamma), self.gamma_parity)
		self.x_w_b = self.w.to_binary(w_b)
		self.x_w_b_parity = w_b.y() & 1
	
	# validates the requested user exists
	# generates a server public key and formats response with salt
	def public_key_exchange(self):
		if self.verbose: print("[*] Receiving data")
		client_username = (self.resp[:self.resp.find(b'\x00')]).decode("utf-8")
		self.x_w_a = self.resp[self.resp.find(b'\x00') + 1:]
		if self.username != client_username:
			print_with_lock("[red][-] Error: invalid username, terminating[/red]\n")
			exit(1)
		assert len(self.x_w_a) == 0x21, \
			print_with_lock("[red][-] Error: invalid client public key length, terminating[/red]")
		if self.verbose: 
			print("    [*] Received username " + client_username)
			print("    [*] Received public key " + binascii.hexlify(self.x_w_a).decode())
			print("    [*] Transmitting username and public key ")
			print("[*] Generating private and public keys")

		self.stage = 1
		self.x_w_a_parity = self.x_w_a[-1]
		self.x_w_a = self.x_w_a[:-1]
		while True:
			self.s_b = secrets.token_bytes(32)
			self.gen_server_public_key()
			if self.w.check(self.w.ecedp(int.from_bytes(self.x_w_b, "big"), self.x_w_b_parity)):
				break
			else: print_with_lock("[red][-] Error: point failed, retrying[/red]")

		if self.verbose: 
			print("    [*] Generated private key " + binascii.hexlify(self.s_b).decode())
			print("    [*] Generated public key " + binascii.hexlify(self.x_w_b).decode())
			print("    [*] Generated salt " + binascii.hexlify(self.salt).decode())
			print("[*] Transmitting public key and salt ")
		self.msg = self.x_w_b + int(self.x_w_b_parity).to_bytes(1, "big") + self.salt + \
			int(self.gamma_parity).to_bytes(1, "big")
		return self.msg

	# call ECPESVDP-SRP-B to generate shared secret and confirm against client confirmation code
	def gen_shared_secret(self):
		if self.verbose: print("    [*] Calling ECPESVDP-SRP-B")
		self.z = self.w.ecpesvdp_srp_b(self.x_w_b, self.gamma, self.x_w_a,
			self.x_w_a_parity, self.s_b, self.gamma_parity)

		# prepare confirmation code and validate 
		self.cc = encryption.get_sha2_digest(self.z)
		if self.verbose: 
			print("    [*] Generated secret key " + binascii.hexlify(self.z).decode())
			print("    [*] Generated confirmation code " + binascii.hexlify(self.cc).decode())
		if self.cc != self.client_cc:
			print_with_lock("[red][-] Error: invalid client cc, check username and password\n[/red]")
			exit(1)
		self.msg = self.cc
		print_with_lock("[bright_green][*] Login successful: " + self.conn_addr[0] + ":" + str(self.conn_addr[1]))
		print_with_lock("\n")
		self.stage = 2
		return self.msg

def new_thread(c, addr: tuple, verbose: bool) -> None:
	c.settimeout(3)
	s = Ecsrp_server(addr, username, password, verbose)
	while True:
		try:
			s.resp = c.recv(1024)
			msg = s.process_msg()
		except socket.timeout:
			print_with_lock(addr[0] + ":" + str(addr[1]) + " timeout")
			c.close()
			exit(0)
		if msg == -1: 
			print_with_lock(addr[0] + ":" + str(addr[1]) + " terminating connection")
			c.close()
			exit(0)
		if msg != b'' and msg != 0: c.send(msg)

if __name__ == "__main__":
	args = argparse.ArgumentParser(description='Winbox Server')
	args.add_argument("-a", "--address", help="host address", required=True)
	args.add_argument("-u", "--username", help="username for authentication", required=True)
	args.add_argument("-password", "--password", help="password for authentication", required=True)
	args.add_argument("-v", "--verbose", help="verbose mode", action="store_true")
	args = vars(args.parse_args())

	username = args["username"]
	password = args["password"]
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind((args["address"], PORT))
	s.listen(5)
	while True:
		c, addr = s.accept()
		print_with_lock("[*] Connected to: " + addr[0] + ":" + str(addr[1]))
		_thread.start_new_thread(new_thread, (c, addr, args["verbose"]))