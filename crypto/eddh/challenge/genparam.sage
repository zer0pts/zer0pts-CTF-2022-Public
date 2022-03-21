def fromMontgomeryCurveToWeierstrassCurve(p, A, B):
    A = GF(p)(A)
    B = GF(p)(B)

    x = A/(3*B) % p
    a = B**(-2) - 3*x**2
    b = -x*(x**2 + a)
    return (a, b)

def fromTwistedEdwardsCurveToMontgomeryCurve(p, a, d):
    a = GF(p)(a)
    d = GF(p)(d)

    A = 2*(a + d)/(a-d)
    B = 4/(a - d)
    return A, B

def fromTwistedEdwardsCurveToWeierstrassCurve(p, a, d):
    A, B = fromTwistedEdwardsCurveToMontgomeryCurve(p, a, d)
    return fromMontgomeryCurveToWeierstrassCurve(p, A, B)

def fromWeierstrassPointToMontgomeryPoint(p, A, B, x, y, mA, mB):
    """
    parameters:
        ( A,  B): weirstrass parameter
        ( x,  y): coordeinates of weirstrass point
        (mA, mB): montgomery parameter
    """
    mA = GF(p)(mA)
    mB = GF(p)(mB)

    u = x*mB - mA/3
    v = y*mB
    return (u, v)

def fromMontgomeryPointToEdwardsPoint(p, mA, mB, mx, my, a, d):
    """
    parameters:
        (mA, mB): montgomery parameter
        (mx, my): coordeinates of montgomery point
        ( a,  d): twisted edwards parameter
    """
    mx = GF(p)(Integer(mx))
    my = GF(p)(Integer(my))

    x = mx / my
    y = (mx-1) / (mx+1)
    return (x, y)

def fromWeierstrassPointToTwistedEdwardsPoint(p, A, B, x, y, a, d):
    """
    parameters:
        (A, B): weirstrass parameter
        (x, y): coordeinates of weirstrass point
        (a, d): twisted edwards parameter
    """
    mA, mB = fromTwistedEdwardsCurveToMontgomeryCurve(p, a, d)
    mx, my = fromWeierstrassPointToMontgomeryPoint(p, A, B, x, y, mA, mB)
    return fromMontgomeryPointToEdwardsPoint(p, mA, mB, mx, my, a, d)

# find a smooth prime
from Crypto.Util.number import getPrime, isPrime
def gen_weak_prime(size, smooth):
    """
    generate approximately size-bit prime p
    which p-1 factorized to p_1 * p_2 * ... * p_n and p_n is up to smooth-bit
    (it means that p-1 is <smooth>-smooth number)
    """
    p = int(2)
    while True:
        if p.bit_length() + smooth >= size:
            p *= getPrime(size - p.bit_length())
            if isPrime(p + 1):
                return p +1
            p = int(2)
        else:
            p *= getPrime(smooth + 1)
p = gen_weak_prime(256, 32)
 

for x in range(1, 10000):
    a = (x + 1) * 4 + 2
    d = 1
    assert not Integer(a*d).is_square()
    assert Integer(d).is_square()

    (A, B) = fromTwistedEdwardsCurveToWeierstrassCurve(p, a, d)
    EC = EllipticCurve(GF(p), [A, B])
    q = EC.order()

    co = 1
    l = q
    while l % 2 == 0:
        co *= 2
        l //= 2
    if not is_prime(l):
        # bad case
        continue

    G = co * EC.gens()[0]  # order of G is l
    x, y = G.xy()
    gx, gy = fromWeierstrassPointToTwistedEdwardsPoint(p, A, B, x, y, a, d)

    print("p = {}".format(p))
    print("a = {}".format(a))
    print("d = {}".format(d))
    print("q = {}".format(q))
    print("c = {}".format(log(co, 2)))
    print("gx = {}".format(gx))
    print("gy = {}".format(gy))
    quit()

