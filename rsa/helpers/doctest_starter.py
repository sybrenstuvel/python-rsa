def run() -> None:
    print("Running doctests 1000x or until failure")
    import doctest

    for count in range(1000):
        (failures, tests) = doctest.testmod()
        if failures:
            break

        if count % 100 == 0 and count:
            print("%i times" % count)

    print("Doctests done")
