from MaxMods.Matrix import *
from MaxMods.Canvas import *
import keyboard as key
import math
import sys
class cube:
    lines = 12
    def __init__(self, master):
        self.root = master
        self.anglex = 0
        self.angley = 0
        self.anglez = 0
        self.sca = 25
        self.transx = 0
        self.transy = 0
        self.transz = 100
        self.fov = 90
        self.near = .1
        self.far = 100000
        self.a = 500/500
        file = ObjLoader('I:/network info/More Extra Space/python scripts ig/AuthMod/3DRender/cube.obj')
        self.cubm = file.vertices
        self.faces =  file.faces
    def transforms(self, pos):
        scaled = Multiply(self.scale, pos)
        rotx = Multiply(self.rotationx, scaled)
        roty = Multiply(self.rotationy, rotx)
        rotz = Multiply(self.rotationz, roty)
        translated = Multiply(self.trans, rotz)
        return self.project(translated)
    def project(self, translated):
        project = Multiply(self.prerspective, translated)
        if project[3][0] != 0:
            for vector in project:
                vector[0] /= project[3][0]
        return project
    def Main(self):
        self.running = True
        while self.running is True:
            self.f = 1/(math.tan((self.fov*.5)/(180*math.pi)))
            self.prerspective = Matrix([[self.a*self.f,0,0,0],[0,self.f,0,0],[0,0,(self.far/(self.far-self.near)),1], [0,0,(self.far*self.near)/(self.far-self.near),0]])
            self.scale = Matrix([[self.sca,0,0,0], [0,self.sca,0,0], [0,0,self.sca,0], [0,0,0,1]])
            self.trans = Matrix([[1,0,0,self.transx], [0,1,0,self.transy], [0,0,1,self.transz], [0,0,0,1]])
            self.rotationx = Matrix([[1,0,0,0],[0,float(math.cos(self.anglex)),float(-math.sin(self.anglex)),0],[0,float(math.sin(self.anglex)),float(math.cos(self.anglex)),0],[0,0,0,1]])
            self.rotationy = Matrix([[float(math.cos(self.angley)),0,float(math.sin(self.angley)),0],[0,1,0,0],[float(-math.sin(self.angley)),0,float(math.cos(self.angley)),0],[0,0,0,1]])
            self.rotationz = Matrix([[float(math.cos(self.anglez)),float(-math.sin(self.anglez)),0,0],[float(math.sin(self.anglez)),float(math.cos(self.anglez)),0,0],[0,0,1,0],[0,0,0,1]])
            for i,(a,b,c) in enumerate(self.faces):
                pos1 = Matrix([[self.cubm[a][0]], [self.cubm[a][1]], [self.cubm[a][2]], [self.cubm[a][3]]])
                pos2 = Matrix([[self.cubm[b][0]], [self.cubm[b][1]], [self.cubm[b][2]], [self.cubm[b][3]]])
                pos3 = Matrix([[self.cubm[c][0]], [self.cubm[c][1]], [self.cubm[c][2]], [self.cubm[c][3]]])
                project1 = self.transforms(pos1)
                project2 = self.transforms(pos2)
                project3 = self.transforms(pos3)
                self.root.triangle([[project1[0][0]+250, project1[1][0]+250], [project2[0][0]+250, project2[1][0]+250], [project3[0][0]+250, project3[1][0]+250]],i+1)
            if key.is_pressed('w') is True:
                self.anglex -= .01
            if key.is_pressed('a') is True:
                self.angley += .01
            if key.is_pressed('s') is True:
                self.anglex += .01
            if key.is_pressed('d') is True:
                self.angley -= .01
            if key.is_pressed('e') is True:
                self.anglez += .01
            if key.is_pressed('q') is True:
                self.anglez -= .01
            if key.is_pressed('Escape') is True:
                self.stop()
    def stop(self):
        self.running = False
        sys.exit()
class ObjLoader(object):
    def __init__(self, fileName):
        self.vertices = []
        self.faces = []
        self.tagmin = 0
        self.taglength = 0
        try:
            f = open(fileName)
            for line in f:
                if line[:2] == "v ":
                    index1 = line.find(" ") + 1
                    index2 = line.find(" ", index1 + 1)
                    index3 = line.find(" ", index2 + 1)
                    vertex = [int(line[index1:index2]), int(line[index2:index3]), int(line[index3:-1])]
                    vertex = [round(vertex[0], 2), round(vertex[1], 2), round(vertex[2], 2), 1]
                    self.vertices.append(vertex)
                elif line[0] == "f":
                    string = line.replace("//", "/")
                    i = string.find(" ") + 1
                    face = []
                    for item in range(string.count(" ")):
                        if string.find(" ", i) == -1:
                            face.append(int(string[i:-1])-1)
                            break
                        face.append(int(string[i:string.find(" ", i)])-1)
                        i = string.find(" ", i) + 1
                    self.faces.append(list(face))
            f.close()
        except IOError as err:
            raise Exception(err)
Canvas(cube, 500, 500)