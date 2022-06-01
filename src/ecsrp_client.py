import elliptic_curves, encryption
import time, socket, binascii, secrets, argparse
from rich import print

class Ecsrp_client:
    def __init__(self, host: str, verbose: bool, port: int = 7777):
        self.verbose = verbose
        self.host = host
        self.port = port
        self.username = 'admin'
        self.password = ''
        self.socket = None
        self.stage = -1
        self.w = elliptic_curves.WCurve()
        self.s_a = b''
        self.w_a = None
        self.w_a_x = b''
        self.w_a_x_parity = -1
        self.w_b_x = b''
        self.w_b_x_parity = -1
        self.z = b''
        self.cc = b''
        self.v_private = b''
        self.i = b''
        self.msg = b''
        self.resp = b''

    def close(self):
        self.socket.close()
        if self.verbose: print("[*] Session terminated")

    # ECPESVDP-SRP-A generates the shared secret using the server-side data
    def gen_shared_secret(self, salt: bytes, gamma_parity: bool):
        if self.verbose: print("    [*] Calling ECPESVDP-SRP-A")
        self.z = self.w.ecpesvdp_srp_a(self.username, self.password, salt, self.w_b_x, 
            self.w_b_x_parity, self.s_a, gamma_parity)

    # performs authentication in a linear manner
    # looped to retry if any errors occur
    def auth(self, username: str, password: str):

        def open_socket():
            print("[*] Opening socket")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((self.host, self.port))
            s.settimeout(3)
            self.socket = s
            if self.verbose: print("[*] Connected to host")
            self.stage = 0

        # simple ECPEPKGP-SRP-A algorithm to generate public key
        def public_key_exchange():
            if self.verbose: print("[*] Starting key exchange")
            self.s_a = secrets.token_bytes(32)
            if self.verbose: print("    [*] Calling ECPEPKGP-SRP-A")
            self.w_a = self.w.ecpepkgp_srp_a(self.s_a)
            self.w_a_x = self.w.to_binary(self.w_a)
            self.w_a_x_parity = self.w_a.y() & 1
            if not self.w.check(self.w.ecedp(int.from_bytes(self.w_a_x, "big"), 
                self.w_a_x_parity)):
                self.stage = -1
            self.msg = username.encode('utf-8') + b'\x00'
            self.msg += self.w_a_x + int(self.w_a_x_parity).to_bytes(1, "big")
            if self.verbose: 
                print("    [*] Generated private key " + binascii.hexlify(self.s_a).decode())
                print("    [*] Generated public key " + binascii.hexlify(self.w_a_x).decode())
                print("[*] Transmitting username and public key ")
            self.stage = 1

        # handles server response and performs ECPESVDP-SRP-A to compute shared secret, z
        # uses z for confirmation code, cc, and formats response to confirm shared secret
        def confirmation():
            if self.verbose: print("[*] Receiving data")
            if len(self.resp) != 0x32:
                print("[red][-] Error: challenge response corrupted. Retrying...\n")
                self.stage = -1
                exit(0)
                return
            self.w_b_x = self.resp[:0x20]
            self.w_b_x_parity = self.resp[0x20]
            salt = self.resp[0x21:0x31]
            gamma_parity = self.resp[0x31]
            if self.verbose: 
                print("    [*] Received public key " + binascii.hexlify(self.w_b_x).decode())
                print("    [*] Received salt " + binascii.hexlify(salt).decode())
                print("    [*] Transmitting username and public key ")
                print("[*] Generating shared secret")
            self.gen_shared_secret(salt, gamma_parity)
            self.cc = encryption.get_sha2_digest(self.z)
            if self.verbose: 
                print("    [*] Generated secret key " + binascii.hexlify(self.z).decode())
                print("    [*] Generated confirmation code " + binascii.hexlify(self.cc).decode())
                print("[*] Transmitting confirmation code ")
            self.msg = self.cc
            self.stage = 2
            
        self.username = username
        self.password = password
                
        while True:
            if self.stage == -1: 
                if self.socket != None: self.socket.close()
                open_socket()
            elif self.stage == 0:
                public_key_exchange()
            elif self.stage == 1: 
                confirmation()
            elif self.stage == 2:
                if self.resp != self.cc:
                    print("[red][-] Error: mismatched confirmation key. Retrying...\n")
                    self.stage = -1
                else:   
                    print("[bright_green][*] Authentication complete, terminating")
                    self.close()
                    exit(0)

            if self.msg != b'' and self.socket != None:
                self.socket.send(self.msg)
                self.msg = b''
                try:
                    self.resp = self.socket.recv(1024)
                except socket.timeout:
                    print("[red][-] Error: server timeout. Retrying...\n")
                    self.stage = -1
            
        return 0

if __name__ == "__main__":
    args = argparse.ArgumentParser(description='Ecsrp_client Client')
    args.add_argument("-a", "--address", help="server address", required=True)
    args.add_argument("-u", "--username", help="username", required=True)
    args.add_argument("-p", "--password", help="password", default="")
    args.add_argument("-v", "--verbose", help="verbose mode", action="store_true")
    args = vars(args.parse_args())

    e = Ecsrp_client(args["address"], args["verbose"])
    e.auth(args["username"], args["password"])