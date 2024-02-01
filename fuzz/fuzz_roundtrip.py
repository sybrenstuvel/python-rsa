import sys
import atheris

with atheris.instrument_imports():
    import rsa

@atheris.instrument_func
def TestOneInput(input_bytes):
    fdp = atheris.FuzzedDataProvider(input_bytes)
    key = fdp.ConsumeIntInRange(16, 9999)
    message = fdp.ConsumeBytes(atheris.ALL_REMAINING)

    try:
        pub, priv = rsa.newkeys(key)
    except ValueError:
        # newskeys raises a ValueError in the event of a legit error. The fuzzer
        # will often generate input that triggers such errors, and we can simply
        # ignore them, although the fuzzer should continue running and thus we
        # return.
        return

    try:
        encrypted = rsa.encrypt(message, pub)
    except OverflowError:
        # encrypt calls into _pad_for_encryption which raises an overflow error.
        # Similar to above, the fuzzer will generate inputs that trigger this
        # exception and in this event we simply want the fuzzer to continue.
        # As such, we return so the fuzzer can continue with its next iteration.
        return

    decrypted = rsa.decrypt(encrypted, priv)
    assert(decrypted == message)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
