import time

class timer:
    def __init__(self):
        pass
    def run_time(self, func, *args, **kwargs):
        '''
        prints time to process a function and returns its value
        '''
        if callable(func):
            t1 = time.perf_counter()
            val = func(*args, **kwargs)
            t2 = time.perf_counter()
            self.message = f"Ran '{func.__name__}' in {t2 - t1:0.4f} seconds"
            return val
        else:
            raise Exception("function not callable")