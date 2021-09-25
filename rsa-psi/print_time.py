from time import time

__all__ = ['print_time']

def print_time(func):
    """Decorator of viewing function runtime.
    eg:
        ```py
        from print_time import print_time as pt
        @pt
        def work(...):
            print('work is running')
        work()
        ```
    """
    def fi(*args, **kwargs):
        t_start = time()
        result = func(*args, **kwargs)
        t_end = time()
        t_diff = t_end - t_start
        print(f"[TIMER] function '{func.__name__}' took {t_diff * 1000}ms")
        return result 
    return fi

# test
@print_time
def _test():
    print('_test is running')

if __name__ == '__main__':
    _test()