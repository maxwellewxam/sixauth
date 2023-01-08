import time

class Timer:
    def __init__(self):
        pass
    def run_time(self, func, *args, text = None, **kwargs):
        '''
        prints time to process a function and returns its value
        '''
        if callable(func):
            t1 = time.perf_counter()
            val = func(*args, **kwargs)
            t2 = time.perf_counter()
            if text is None:
                self.message = f"Ran '{func.__name__}' in {t2 - t1:0.4f} seconds"
            else:
                self.message = f"Ran '{text}' in {t2 - t1:0.4f} seconds"
            return val
        else:
            raise Exception("function not callable")

import robot
with robot.Connect() as bot:
    for _ in range(3):
        bot.MOVE_FORWARD()
    bot.ROTATE_LEFT()
    for _ in range(2):
        bot.MOVE_FORWARD()
with robot.Connect() as bot:
    def right(self):
        for _ in range(3):
            self.ROTATE_LEFT()
    bot.ROTATE_RIGHT = right
    for _ in range(2):
        bot.MOVE_FORWARD()
    bot.ROTATE_LEFT()
    for _ in range(4):
        bot.MOVE_FORWARD()
    bot.ROTATE_RIGHT()
    for _ in range(2):
        bot.MOVE_FORWARD()

x, y = (1,2)
x, y = (y,x)
print(x, y)
