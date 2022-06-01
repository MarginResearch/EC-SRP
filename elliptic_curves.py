import binascii, hashlib, encryption
import ecdsa

# Euler's equation for determining the greatest common denominator
def _egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# finds the multiplicative modular inverse of a for modulus p
def _modinv(a: int, p: int):
    if a < 0:
        a = a % p
    g, x, y = _egcd(a, p)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % p

def _legendre_symbol(a: int, p: int):
    l = pow(a, (p - 1)//2, p)
    if l == p - 1:
        return -1
    return l

# courtesy of Phong (https://codereview.stackexchange.com/questions/43210/
#   tonelli-shanks-algorithm-implementation-of-prime-modular-square-root)
def _prime_mod_sqrt(a: int, p: int):

    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]

    if _legendre_symbol(a, p) != 1:
        return []
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return [x, p - x]

    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2

    z = 1
    while _legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)

    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i

    return [x, p - x]

class WCurve: 
    def __init__(self): 
        self.__p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        self.__r = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
        self.__mont_a = 486662
        self.__conversion_from_m = self.__mont_a * _modinv(3, self.__p) % self.__p
        self.__conversion = (self.__p - self.__mont_a * _modinv(3, self.__p)) % self.__p
        self.__a = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
        self.__b = 0x7b425ed097b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864
        self.__h = 8
        self.__curve = ecdsa.ellipticcurve.CurveFp(self.__p, self.__a, self.__b,self. __h)
        self.__g = self.ecedp(0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaad245a, 1)

    # plots the private key on the elliptic curve, returning the public key point
    def plot(self, priv: bytes) -> ecdsa.ellipticcurve.PointJacobi:
        assert len(priv) == 32
        priv = int.from_bytes(priv, "big")
        return priv * self.__g

    # converts a point's x coordinate to binary to use as a public key
    def to_binary(self, pt: ecdsa.ellipticcurve.PointJacobi) -> bytes:
        assert type(pt) == ecdsa.ellipticcurve.PointJacobi 
        # or type(pt) == ecdsa.ellipticcurve.Point
        x = pt.x() % self.__p
        return int(x).to_bytes(32, "big")

    # Lifts the input x value on the Weierstrass curve, returning point pt = (x, y)
    # returns either the even or odd y coordinate based on the input boolean
    def ecedp(self, x: int, parity: bool) -> ecdsa.ellipticcurve.PointJacobi:
        while True: 
            x %= self.__p
            y_squared = (x**3 + self.__a * x + self.__b) % self.__p
            ys = _prime_mod_sqrt(y_squared, self.__p)
            if ys != []:
                pt1 = ecdsa.ellipticcurve.PointJacobi(self.__curve, 
                    x, ys[0], 1, self.__r)
                pt2 = ecdsa.ellipticcurve.PointJacobi(self.__curve, 
                    x, ys[1], 1, self.__r)
                if pt1.y() & 1 == 1 and parity != 0:   return pt1
                elif pt2.y() & 1 == 1 and parity != 0: return pt2
                elif pt1.y() & 1 == 0 and parity == 0: return pt1
                else:                                  return pt2
            else:
                x = x + 1

    # plot's the client's private key and returns the public key point
    def ecpepkgp_srp_a(self, s: bytes) -> ecdsa.ellipticcurve.PointJacobi:
        return self.plot(s)

    # performs the client's shared secret calculation
    def ecpesvdp_srp_a(self, username: str, password: str, salt: bytes, 
        x_w_b: bytes, w_b_parity: bool, s: bytes, gamma_parity: bool):
        gamma, gamma_parity, i = self.ecpvdgp_srp(username, password, salt)
        x_gamma = self.to_binary(gamma)
        x_gamma = encryption.get_sha2_digest(x_gamma)
        pt = self.ecedp(int.from_bytes(x_gamma, "big") % self.__p, not gamma_parity)
        server_pt = self.ecedp(int.from_bytes(x_w_b, "big"), 
            w_b_parity)
        server_pt += pt
        
        j = encryption.get_sha2_digest(x_w_b)
        ij = int.from_bytes(i, "big") * int.from_bytes(j, "big")
        ij += int.from_bytes(s, "big")
        # mod by curve order to ensure the result is a point within the finite field
        ij = self.finite_field_value(ij) 
        return self.to_binary(ij * server_pt)

    # plot's the client's private key and returns the public key point
    # the server's public key includes pseudo-random data based on the username and 
    # password validation point, gamma
    def ecpepkgp_srp_b(self, s: bytes, x_gamma: bytes, parity: bool) \
        -> ecdsa.ellipticcurve.PointJacobi:
        pub = self.plot(s)
        x_gamma = hashlib.sha256(x_gamma).digest()
        x_gamma_point = self.ecedp(int.from_bytes(x_gamma, "big") % self.__p, parity)
        return pub + x_gamma_point

    # performs the server's shared secret calculation
    def ecpesvdp_srp_b(self, x_w_b: bytes, gamma: ecdsa.ellipticcurve.PointJacobi,
        client_public: bytes, client_public_parity: bool, s: bytes, gamma_parity: bool):
        j = int.from_bytes(encryption.get_sha2_digest(x_w_b), "big")
        x_gamma = self.to_binary(gamma)
        gamma = self.ecedp(int.from_bytes(x_gamma, "big"), gamma_parity)
        pt = gamma * j
        w_a = self.ecedp(int.from_bytes(client_public, "big"), client_public_parity)
        pt = pt + w_a
        pt *= (int.from_bytes(s, "big"))
        return self.to_binary(pt)

    # calculates the password validator input, i, and password validator point, gamma
    # also returns gamma's parity, which is used to add / subtract the gamma point appropriately 
    def ecpvdgp_srp(self, username: str, password: str, salt: bytes) -> tuple:
        assert len(salt) == 0x10, print("[-] Error: salt must be 16 bytes")
        i = hashlib.sha256(salt + hashlib.sha256((username + ":" + password).encode("utf-8")).digest()).digest()
        gamma = self.plot(i)
        return gamma, gamma.y() & 1, i

    # checks that the input point is on the Weierstrass curve
    def check(self, a: ecdsa.ellipticcurve.PointJacobi):
        left = (a.y()**2) % self.__p
        right = (a.x()**3 + self.__a * a.x() * 1**4 + self.__b * 1**6) % self.__p
        return left == right

    # reduces the input scalar value over the curve's finite field
    def finite_field_value(self, a: int):
        return a % self.__r