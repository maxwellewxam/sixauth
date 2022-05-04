from MaxMods import Matrix as mat
from MaxMods import Canvas as can
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
        self.near = float(.1)
        self.far = 1000
        self.a = 500/500
        self.f = 1/(math.tan((self.fov*.5)/(180*math.pi)))
        self.cubm = mat.Matrix([[0,1,0,1], [1,-1,1,1], [-1, -1, 1,1], [-1,-1,-1,1], [1, -1, -1,1]])
        self.faces =  [(0,1), (0,2), (0,3), (0,4), (1,2), (1,3), (2,3), (3,4), (4,1)]
        self.prerspective = mat.Matrix([[self.a*self.f,0,0,0],[0,self.f,0,0],[0,0,(self.far/(self.far-self.near)),1], [0,0,(self.far*self.near)/(self.far-self.near),0]])
    def transforms(self, pos):
        scaled = mat.Multiply(self.scale, pos)
        rotx = mat.Multiply(self.rotationx, scaled)
        roty = mat.Multiply(self.rotationy, rotx)
        rotz = mat.Multiply(self.rotationz, roty)
        translated = mat.Multiply(self.trans, rotz)
        project = mat.Multiply(self.prerspective, translated)
        if project[3][0] != 0:
            for vector in project:
                vector[0] /= project[3][0]
        return project
    def Main(self):
        self.running = True
        while self.running is True:
            self.scale = mat.Matrix(str(self.sca) + ' 0 0 0; 0 ' + str(self.sca) + ' 0 0; 0 0 ' + str(self.sca) + ' 0; 0 0 0 1')
            self.trans = mat.Matrix('1 0 0 ' + str(self.transx) + '; 0 1 0 ' + str(self.transy) + '; 0 0 1 ' + str(self.transz) + '; 0 0 0 1')
            self.rotationx = mat.Matrix([[1,0,0,0],[0,float(math.cos(self.anglex)),float(-math.sin(self.anglex)),0],[0,float(math.sin(self.anglex)),float(math.cos(self.anglex)),0],[0,0,0,1]])
            self.rotationy = mat.Matrix([[float(math.cos(self.angley)),0,float(math.sin(self.angley)),0],[0,1,0,0],[float(-math.sin(self.angley)),0,float(math.cos(self.angley)),0],[0,0,0,1]])
            self.rotationz = mat.Matrix([[float(math.cos(self.anglez)),float(-math.sin(self.anglez)),0,0],[float(math.sin(self.anglez)),float(math.cos(self.anglez)),0,0],[0,0,1,0],[0,0,0,1]])
            for i,(a,b) in enumerate(self.faces):
                pos1 = mat.Matrix([[self.cubm[a][0]], [self.cubm[a][1]], [self.cubm[a][2]], [self.cubm[a][3]]])
                pos2 = mat.Matrix([[self.cubm[b][0]], [self.cubm[b][1]], [self.cubm[b][2]], [self.cubm[b][3]]])
                project1 = self.transforms(pos1)
                project2 = self.transforms(pos2)
                self.root.line([[project1[0][0]+250, project1[1][0]+250], [project2[0][0]+250, project2[1][0]+250]],i+1)
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
can.Canvas(cube, 500, 500)