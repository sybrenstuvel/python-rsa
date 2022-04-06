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
        return

    try:
        encrypted = rsa.encrypt(message, pub)
    except OverflowError:
        return

    decrypted = rsa.decrypt(encrypted, priv)
    assert(decrypted == message)


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput, enable_python_coverage=True)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
