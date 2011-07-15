import re
import unittest

from . import bcrypt
from lib.eksblowfish import EksBlowfish
from nose.tools import eq_


class BcryptTestCase(unittest.TestCase):
    def test_gensalt(self):
        """Salt generation should do something useful."""
        a = bcrypt.gensalt(4)
        b = bcrypt.gensalt(4)
        assert a != b

        # Salts look like: '$2a$04$JaLL9GgWK2Y.Ek27R27rMQ'
        salt_re = re.compile(r'^\$2a\$04\$[0-9a-zA-z/.]{22}$')
        assert salt_re.match(a)
        assert salt_re.match(b)

    def test_hashpw(self):
        """Test password hashing, with known salt."""
        salt = '$2a$04$e9aKlXB7x0Uacbi7tRyKA.'
        should_be = ('$2a$04$e9aKlXB7x0Uacbi7tRyKA.ZE1qLWlAKZiMV9P2q8bI.'
                     'azUYj2EcFS')

        hashed = bcrypt.hashpw('abc', salt)

        eq_(hashed, should_be)

    def test_base64(self):
        """Test bcrypt's awkward implementation of base64."""
        something = 'abcdef'
        eq_(something, bcrypt._b64_decode(bcrypt._b64_encode(something)))


class BlowfishTestCase(unittest.TestCase):
    def setUp(self):
        self.bf = EksBlowfish()

    def test_round_func(self):
        """Blowfish-internal shuffling function."""
        eq_(self.bf._round_func(12345678), 482594201)
        eq_(self.bf._round_func(87654321), 3752855962)

    def test_cipher(self):
        """Test blowfish cipher."""
        xl = 123456
        xr = 654321

        cl, cr = self.bf.cipher(xl, xr, self.bf.ENCRYPT)
        dl, dr = self.bf.cipher(cl, cr, self.bf.DECRYPT)
        eq_((xl, xr), (dl, dr))
