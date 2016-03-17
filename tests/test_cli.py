"""
Unit tests for CLI entry points.
"""

import unittest
import sys
import functools
from contextlib import contextmanager

import os
from io import StringIO, BytesIO

import rsa
import rsa.cli

if sys.version_info[0] < 3:
    IOClass = BytesIO
else:
    IOClass = StringIO


@contextmanager
def captured_output():
    """Captures output to stdout and stderr"""

    new_out, new_err = IOClass(), IOClass()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = new_out, new_err
        yield sys.stdout, sys.stderr
    finally:
        sys.stdout, sys.stderr = old_out, old_err


@contextmanager
def cli_args(*new_argv):
    """Updates sys.argv[1:] for a single test."""

    old_args = sys.argv[:]
    sys.argv[1:] = [str(arg) for arg in new_argv]

    try:
        yield
    finally:
        sys.argv[1:] = old_args


def cleanup_files(*filenames):
    """Makes sure the files don't exist when the test runs, and deletes them afterward."""

    def remove():
        for fname in filenames:
            if os.path.exists(fname):
                os.unlink(fname)

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            remove()
            try:
                return func(*args, **kwargs)
            finally:
                remove()

        return wrapper

    return decorator


class AbstractCliTest(unittest.TestCase):
    def assertExits(self, status_code, func, *args, **kwargs):
        try:
            func(*args, **kwargs)
        except SystemExit as ex:
            if status_code == ex.code:
                return
            self.fail('SystemExit() raised by %r, but exited with code %i, expected %i' % (
                func, ex.code, status_code))
        else:
            self.fail('SystemExit() not raised by %r' % func)


class KeygenTest(AbstractCliTest):
    def test_keygen_no_args(self):
        with cli_args():
            self.assertExits(1, rsa.cli.keygen)

    def test_keygen_priv_stdout(self):
        with captured_output() as (out, err):
            with cli_args(128):
                rsa.cli.keygen()

        lines = out.getvalue().splitlines()
        self.assertEqual('-----BEGIN RSA PRIVATE KEY-----', lines[0])
        self.assertEqual('-----END RSA PRIVATE KEY-----', lines[-1])

        # The key size should be shown on stderr
        self.assertTrue('128-bit key' in err.getvalue())

    @cleanup_files('test_cli_privkey_out.pem')
    def test_keygen_priv_out_pem(self):
        with captured_output() as (out, err):
            with cli_args('--out=test_cli_privkey_out.pem', '--form=PEM', 128):
                rsa.cli.keygen()

        # The key size should be shown on stderr
        self.assertTrue('128-bit key' in err.getvalue())

        # The output file should be shown on stderr
        self.assertTrue('test_cli_privkey_out.pem' in err.getvalue())

        # If we can load the file as PEM, it's good enough.
        with open('test_cli_privkey_out.pem', 'rb') as pemfile:
            rsa.PrivateKey.load_pkcs1(pemfile.read())

    @cleanup_files('test_cli_privkey_out.der')
    def test_keygen_priv_out_der(self):
        with captured_output() as (out, err):
            with cli_args('--out=test_cli_privkey_out.der', '--form=DER', 128):
                rsa.cli.keygen()

        # The key size should be shown on stderr
        self.assertTrue('128-bit key' in err.getvalue())

        # The output file should be shown on stderr
        self.assertTrue('test_cli_privkey_out.der' in err.getvalue())

        # If we can load the file as der, it's good enough.
        with open('test_cli_privkey_out.der', 'rb') as derfile:
            rsa.PrivateKey.load_pkcs1(derfile.read(), format='DER')

    @cleanup_files('test_cli_privkey_out.pem', 'test_cli_pubkey_out.pem')
    def test_keygen_pub_out_pem(self):
        with captured_output() as (out, err):
            with cli_args('--out=test_cli_privkey_out.pem',
                          '--pubout=test_cli_pubkey_out.pem',
                          '--form=PEM', 256):
                rsa.cli.keygen()

        # The key size should be shown on stderr
        self.assertTrue('256-bit key' in err.getvalue())

        # The output files should be shown on stderr
        self.assertTrue('test_cli_privkey_out.pem' in err.getvalue())
        self.assertTrue('test_cli_pubkey_out.pem' in err.getvalue())

        # If we can load the file as PEM, it's good enough.
        with open('test_cli_pubkey_out.pem', 'rb') as pemfile:
            rsa.PublicKey.load_pkcs1(pemfile.read())
