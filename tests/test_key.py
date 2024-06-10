"""
Some tests for the rsa/key.py file.
"""

import rsa.key
import rsa.logic


def test_blinding():
    """Test blinding and unblinding.

    This is basically the doctest of the PrivateKey.blind method, but then
    implemented as unittest to allow running on different Python versions.
    """

    pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

    message = 12345
    encrypted = rsa.logic.encrypt_int(message, pk.e, pk.n)

    blinded_1, unblind_1 = pk.blind(encrypted)  # blind before decrypting
    decrypted = rsa.logic.decrypt_int(blinded_1, pk.d, pk.n)

    assert pk.unblind(decrypted, unblind_1) == message

    # Re-blinding should use a different blinding factor.
    blinded_2, unblind_2 = pk.blind(encrypted)  # blind before decrypting
    assert blinded_1 != blinded_2

    # The unblinding should still work, though.
    decrypted = rsa.logic.decrypt_int(blinded_2, pk.d, pk.n)

    assert pk.unblind(decrypted, unblind_2) == message


def test_custom_exponent():
    public, private = rsa.key.new_keys(16, exponent=3)

    assert private.e == 3
    assert public.e == 3


def test_default_exponent():
    public, private = rsa.key.new_keys(16)

    assert private.e == 0x10001
    assert public.e == 0x10001


def test_exponents_coefficient_calculation():
    pk = rsa.key.PrivateKey(3727264081, 65537, 3349121513, 65063, 57287)

    assert pk.exp1 == 55063
    assert pk.exp2 == 10095
    assert pk.coef == 50797


def test_custom_get_prime_func():
    # List of primes to test with, in order [p, q, p, q, ....]
    # By starting with two of the same primes, we test that this is
    # properly rejected.
    primes = [64123, 64123, 64123, 50957, 39317, 33107]

    # This exponent will cause two other primes to be generated.
    exponent = 136407

    p, q, e, d = rsa.key.gen_keys(
        64,
        accurate=False,
        get_prime_func=lambda x: primes.pop(0),
        exponent=exponent
    )

    assert p == 39317
    assert q == 33107


def test_multiprime():
    primes = [64123, 50957, 39317, 33107]
    exponent = 2**2**4 + 1

    p, q, e, d, rs = rsa.key.gen_keys(
        128,
        accurate=False,
        get_prime_func=lambda x: primes.pop(0),
        exponent=exponent,
        n_primes=4
    )
    assert p == 64123
    assert q == 50957
    assert rs == [39317, 33107]


def test_hash_possible():
    public, private = rsa.key.new_keys(16)

    # This raises a TypeError when hashing isn't possible.
    hash(private)
    hash(public)
