import time

value = 'testing123'


def tester():
    return 'testing123'


def test():
    start_time = time.time()
    print(value)
    print('time taken for text is ', time.time() - start_time)

    start_time = time.time()
    print(tester())
    print('time taken for function is ', time.time() - start_time)


test()
