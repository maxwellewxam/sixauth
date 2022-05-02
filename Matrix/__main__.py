class Matrix():
    def __init__(self, Array):
        self.Array = Array
        self.Array2 = self.copy()
    def copy(self):
        Array = []
        for item in enumerate(self.Array):
            Array.append(item)
        return Array
    def index(self, row = 1, column = 1, value = 0):
        try:
            self.Array[row]
        except:
            for _ in range(row - len(self.Array) + 1):
                self.Array.insert(len(self.Array), [])
        temp = self.Array[row]
        try:
            temp.pop(column)
        except:
            pass
        temp.insert(column, value)
    def print(self):
        for i in range(len(self.Array)):
            for x in range(len(self.Array[i])):
                print((self.Array[i][x]), end = ' ')
            print()
        print()
    def modular(self, mod):
        for i in range(len(self.Array)):
            for x in range(len(self.Array[i])):
                if self.Array[i][x] % mod != 0:
                    self.Array2[i][x] = 0
        return self.Array2
    def sum(self):
        val = 0
        for i in range(len(self.Array)):
            for x in range(len(self.Array[i])):
                val += self.Array[i][x]
        return val
    def average(self):
        return self.sum() / (len(self.Array) * len(self.Array[1]))
    def rotate(self, turn = 1, Return = True):
        for _ in range(turn):
            self.Array2 = list(zip(*self.Array2))[::-1]
        if Return == True:
            return [list(elem) for elem in self.arry2]
        else:
            self.Array = self.copy([list(elem) for elem in self.Array2])
    def flip(self, direction = 'Row', Return = True):
        import copy
        if direction == 'Row':
            for i in range(len(self.arry)):
                self.arry2[i] = self.arry[i][::-1]
        if direction == 'Column':
            self.arry2 = self.arry[::-1]
        if Return == True:
            return self.arry2
            self.arry2 = copy.deepcopy(self.arry)
        else:
            self.arry = copy.deepcopy(self.arry2)
class Multiply(Matrix):
    def __init__(self, mA, mB):
        self.arry = []
        super().__init__(array = self.arry)
        rowtemp = 0
        columntemp = 0
        temp = 0
        if len(mA.arry[1]) == len(mB.arry):
                for a in range(len(mA.arry)):
                    for b in range(len(mB.arry[1])):
                        for c in range(len(mB.arry)):
                            temp += mA.arry[a][c] * mB.arry[c][b]
                        self.index(row = rowtemp, column = columntemp, value = temp)
                        temp = 0
                        columntemp += 1
                    rowtemp += 1
class Add(Matrix):
    def __init__(self, mA, mB):
        import copy
        self.arry = []
        for i in range(len(mA.arry)):
            for x in range(len(mB.arry[i])):
                temp = mA.arry[i][x] + mB.arry[i][x]
                self.index(row = i, column = x, value = temp)
        super().__init__(array = self.arry)