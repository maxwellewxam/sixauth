import tkinter as tk
import queue
import threading
import time
import sys
import fpstimer
from func_timeout import func_timeout, FunctionTimedOut
class MainGui:
    def __init__(self, master, worker, height, width):
        self.start = worker.start
        self.stop = worker.stop
        self.queue = worker.queue
        self.worker = worker
        self.master = master
        self.master.geometry(f'{width+4}x{height+4}')
        self.master.resizable(False, False)
        self.master.title('3D Render')
        self.canvas = tk.Canvas(self.master, width = width, height = height, bg = 'black')
        self.canvas.bind('<Map>', self.start)
        self.canvas.bind('<Destroy>', self.stop)
        self.canvas.grid(row = 0, column = 0)
        self.tagdict = {}
    def processIncoming(self):
        while self.queue.qsize():
            try:
                msg = self.queue.get()
                if msg[0] not in self.tagdict.keys():
                    if msg[2] == 1:
                        try:
                            id = func_timeout(.5, self.canvas.create_line, (msg[1][0], msg[1][1]))
                            self.canvas.itemconfig(id, fill=msg[3])
                            self.tagdict[msg[0]] = id
                        except FunctionTimedOut  as err:
                            sys.exit()
                    if msg[2] == 2:
                        try:
                            id = func_timeout(.5, self.canvas.create_polygon, (msg[1][0], msg[1][1], msg[1][2]))
                            self.canvas.itemconfig(id, fill=msg[3])
                            self.tagdict[msg[0]] = id
                        except FunctionTimedOut  as err:
                            sys.exit()
                else:
                    if msg[2] == 1:
                        try:
                            func_timeout(.5, self.canvas.coords, (self.tagdict[msg[0]], *msg[1][0], *msg[1][1]))
                            self.canvas.itemconfig(self.tagdict[msg[0]], fill=msg[3])
                        except FunctionTimedOut as err:
                            sys.exit()
                    if msg[2] == 2:
                        try:
                            func_timeout(.5, self.canvas.coords, (self.tagdict[msg[0]], *msg[1][0], *msg[1][1], *msg[1][2]))
                            self.canvas.itemconfig(self.tagdict[msg[0]], fill=msg[3])
                        except FunctionTimedOut as err:
                            sys.exit()
            except queue.Empty:
                pass
class ThreadedClient:
    def __init__(self, master, shape, height, width):
        self.master = master
        self.shape = shape
        self.started = False
        self.queue = queue.Queue(maxsize = 1)
        self.gui = MainGui(master, self, height, width)
    def workerThread1(self):
        try:
            self.queue.put([1,self.shape.lines])
            self.gui.processIncoming()
        except:
            pass
        try:
            self.queue.put([2,self.shape.triangle])
            self.gui.processIncoming()
        except:
            pass
        self.run = self.shape(self)
        t = threading.current_thread()
        timer = fpstimer.FPSTimer(60)
        while getattr(t, "do_run", True):
            self.run.Main()
            timer.sleep()
    def start(self, event = None):
        self.thread1 = threading.Thread(target = self.workerThread1, name = 'WorkerThread')
        self.thread1.start()
    def stop(self, event = None):
        self.thread1.do_run = False
        self.thread1.join(.2)
        print('lol')
    def line(self, pos, tag1, color):
        self.queue.put([tag1, pos, 1, color])
        self.gui.processIncoming()
    def triangle(self, pos, tag1, color):
        self.queue.put([tag1, pos, 2, color])
        self.gui.processIncoming()
class Canvas:
    def __init__(self, Handler, Height = 500, Width = 500):
        root = tk.Tk()
        client = ThreadedClient(root, Handler, Height, Width)
        root.mainloop()
        client.stop()