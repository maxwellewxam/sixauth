from copy import deepcopy
class Matrix():
    def __init__(self, Array):
        self.Array = Array
    def __getitem__(self, item):
        return self.Array[item]
    def __len__(self):
        return len(self.Array)
    def copy(self):
        Array2 = []
        for item in self.Array:
            Array2.append(deepcopy(item))
        return Array2
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
        return self
    def print(self):
        for i in range(len(self.Array)):
            for x in range(len(self.Array[i])):
                print((self.Array[i][x]), end = ' ')
            print()
        print()
        return self
    def sum(self):
        val = 0
        for i in range(len(self.Array)):
            for x in range(len(self.Array[i])):
                val += self.Array[i][x]
        return val
    def average(self):
        return self.sum() / (len(self.Array) * len(self.Array[1]))
    def rotate(self, turn = 1):
        for _ in range(turn):
            self.Array2 = list(zip(*self.Array))[::-1]
        self.Array = [list(elem) for elem in self.Array2]
        return self
    def modular(self, ModOf):
        for i in range(len(self.Array)):
            for x in range(len(self.Array[i])):
                if self.Array[i][x] % ModOf != 0:
                    self.index(row = i, column = x, value = 0)
        return self
    def flip(self, direction = 1):
        self.Array2 = self.copy()
        if direction == 1:
            for i in range(len(self.Array)):
                self.Array2[i] = self.Array[i][::-1]
        if direction == 2:
            self.Array2 = self.Array[::-1]
        self.Array = self.Array2
        del(self.Array2)
        return self
    
class Multiply(Matrix):
    def __init__(self, MatA, MatB):
        self.Array = []
        rowtemp = 0
        columntemp = 0
        temp = 0
        if len(MatA[1]) == len(MatB):
            for a in range(len(MatA)):
                for b in range(len(MatB[1])):
                    for c in range(len(MatB)):
                        temp += MatA[a][c] * MatB[c][b]
                    self.index(row = rowtemp, column = columntemp, value = temp)
                    temp = 0
                    columntemp += 1
                rowtemp += 1
                
class Add(Matrix):
    def __init__(self, MatA, MatB):
        self.Array = []
        for i in range(len(MatA.Array)):
            for x in range(len(MatB.Array[i])):
                temp = MatA.Array[i][x] + MatB.Array[i][x]
                self.index(row = i, column = x, value = temp)
