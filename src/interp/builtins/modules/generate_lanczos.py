# Prints LANCZOS_NUMERATOR for math.rs: the numerator of the Lanczos
# approximation Gamma(x) = P(x) / Q(x) * (x + g - 1/2)^(x - 1/2) e^-(x + g - 1/2)
# with N = 13 terms and g = 6.024680040776729583740234375, where
# Q(x) = x (x + 1) ... (x + 11). Requires mpmath:
#
#   python3 generate_lanczos.py
#
# Lanczos writes F(z) = Gamma(z + 1) e^(z + g + 1/2) / (sqrt(2 pi) (z + g + 1/2)^(z + 1/2))
# as p0 / 2 + sum_k p_k H_k(z) with H_k(z) = z (z - 1) ... (z - k + 1) / ((z + 1) ... (z + k)).
# H_k vanishes at the integers 0 .. k - 1, so the exact values F(0) .. F(N - 1)
# determine p_0 .. p_(N-1) by forward substitution. The truncated series is
# then rewritten as partial fractions in z + j and multiplied out over Q.

import mpmath as mp

mp.mp.prec = 400

TERMS = 13
G = mp.mpf("6.024680040776729583740234375")
HALF = mp.mpf(1) / 2


def scaled_gamma(z):
    z = mp.mpf(z)
    return mp.gamma(z + 1) * mp.e ** (z + G + HALF) / (mp.sqrt(2 * mp.pi) * (z + G + HALF) ** (z + HALF))


def h(k, z):
    value = mp.mpf(1)
    for i in range(k):
        value *= mp.mpf(z - i) / (z + i + 1)
    return value


def poly_mul(a, b):
    out = [mp.mpf(0)] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i + j] += x * y
    return out


def numerator():
    p = []
    for ell in range(TERMS):
        if ell == 0:
            p.append(2 * scaled_gamma(0))
            continue
        rest = scaled_gamma(ell) - p[0] / 2 - sum(p[k] * h(k, ell) for k in range(1, ell))
        p.append(rest / h(ell, ell))

    # H_k(z) = 1 + sum_{j=1..k} r_kj / (z + j) with residues r_kj at z = -j.
    constant = p[0] / 2 + sum(p[1:])
    residues = [mp.mpf(0)] * TERMS
    for k in range(1, TERMS):
        for j in range(1, k + 1):
            top = mp.mpf(1)
            for i in range(k):
                top *= -j - i
            bottom = mp.mpf(1)
            for i in range(1, k + 1):
                if i != j:
                    bottom *= i - j
            residues[j] += p[k] * top / bottom

    # With x = z + 1 the poles sit at x = 0, -1, ..., -11.
    q = [mp.mpf(1)]
    for j in range(TERMS - 1):
        q = poly_mul(q, [mp.mpf(j), mp.mpf(1)])
    result = [constant * c for c in q]
    for j in range(1, TERMS):
        part = [mp.mpf(1)]
        for i in range(TERMS - 1):
            if i != j - 1:
                part = poly_mul(part, [mp.mpf(i), mp.mpf(1)])
        part += [mp.mpf(0)] * (len(q) - len(part))
        result = [a + residues[j] * b for a, b in zip(result, part)]
    return [mp.sqrt(2 * mp.pi) * c for c in result]


def main():
    print("const LANCZOS_NUMERATOR: [f64; 13] = [")
    for coefficient in numerator():
        print("    %r," % float(coefficient))
    print("];")


main()
