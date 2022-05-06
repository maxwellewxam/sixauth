from MaxMods.Matrix import *
from MaxMods.Canvas import *
import keyboard as key
import math
import sys
import numpy as np
import pygame
import fpstimer
class cube:
    lines = 12
    def __init__(self, master):
        self.root = master
        self.anglex = 0
        self.angley = 0
        self.anglez = 0
        self.sca = 5
        self.transx = 0
        self.transy = 0
        self.transz = 50
        self.fov = 90
        self.near = .01
        self.far = 1080000
        self.a = 500/500
        self.camera = [0,0,0]
        file = ObjLoader('3DRender/MONKEY.obj')
        self.cubm = file.vertices
        self.faces =  file.faces
    def transforms(self, pos):
        scaled = Multiply(self.scale, pos)
        rotx = Multiply(self.rotationx, scaled)
        roty = Multiply(self.rotationy, rotx)
        rotz = Multiply(self.rotationz, roty)
        translated = Multiply(self.trans, rotz)
        return translated
    def project(self, translated):
        project = Multiply(self.prerspective, translated)
        if project[3][0] != 0:
            for vector in project:
                vector[0] /= project[3][0]
        return project
    def get_color(self, colNum):
        rgbNum = int(255 - ((1-colNum)*225.0))
        Color = (rgbNum,rgbNum,rgbNum)
        return "#%02x%02x%02x" % Color
    def Main(self):
        self.running = True
        while self.running is True:
            self.drawq = []
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
                trans1 = self.transforms(pos1)
                trans2 = self.transforms(pos2)
                trans3 = self.transforms(pos3)
                line1x = trans2[0][0] - trans1[0][0]
                line1y = trans2[1][0] - trans1[1][0]
                line1z = trans2[2][0] - trans1[2][0]
                line2x = trans3[0][0] - trans1[0][0]
                line2y = trans3[1][0] - trans1[1][0]
                line2z = trans3[2][0] - trans1[2][0]
                normalx = line1y * line2z - line1z * line2y
                normaly = line1z * line2x - line1x * line2z
                normalz = line1x * line2y - line1y * line2x
                l = math.sqrt(normalx*normalx+normaly*normaly+normalz*normalz)
                normalx /= l
                normaly /= l
                normalz /= l
                if (normalx * (trans1[0][0] - self.camera[0]) +
                    normaly * (trans1[1][0] - self.camera[1]) +
                    normalz * (trans1[2][0] - self.camera[2]) < 0):
                    project1 = self.project(trans1)
                    project2 = self.project(trans2)
                    project3 = self.project(trans3)
                    light = [0,0,-1]
                    l = math.sqrt(light[0]*light[0]+light[1]*light[1]+light[2]*light[2])
                    light[0] /= l
                    light[1] /= l
                    light[2] /= l
                    dp = normalx * light[0] + normaly * light[1] + normalz * light[2]
                    if dp < 0:
                        color = 'black'
                    else:
                        color = self.get_color(dp)
                    self.root.triangle([[project1[0][0]+250, project1[1][0]+250], [project2[0][0]+250, project2[1][0]+250], [project3[0][0]+250, project3[1][0]+250]],i, color)
                else:
                    self.root.triangle([[0,0],[0,0],[0,0]],i, 'black')
            if key.is_pressed('w') is True:
                self.anglex -= .1
            if key.is_pressed('a') is True:
                self.angley += .1
            if key.is_pressed('s') is True:
                self.anglex += .1
            if key.is_pressed('d') is True:
                self.angley -= .1
            if key.is_pressed('e') is True:
                self.anglez += .1
            if key.is_pressed('q') is True:
                self.anglez -= .1
            if key.is_pressed('Escape') is True:
                self.stop()
    def stop(self):
        self.running = False
        sys.exit()

class Renderer:
    def __init__(self):
        file = ObjLoader('3DRender/MONKEY.obj')
        self.cubm = file.vertices
        self.faces = file.faces
        self.anglex = 0
        self.angley = 0
        self.anglez = 0
        self.sca = 10
        self.transx = 0
        self.transy = 0
        self.transz = 50
        self.fov = 90
        self.near = .01
        self.far = 1080000
        self.a = 500/500
        self.camera = [0,0,0,0]
        pygame.init()
        screen = pygame.display.set_mode([500, 500])
        running = True
        timer = fpstimer.FPSTimer(60)
        while running:
            timer.sleep()
            for event in pygame.event.get():
                if event.type == pygame.QUIT:
                    running = False
            if key.is_pressed('w') is True:
                self.anglex -= .1
            if key.is_pressed('a') is True:
                self.angley += .1
            if key.is_pressed('s') is True:
                self.anglex += .1
            if key.is_pressed('d') is True:
                self.angley -= .1
            if key.is_pressed('e') is True:
                self.anglez += .1
            if key.is_pressed('q') is True:
                self.anglez -= .1
            self.f = 1/(np.tan((self.fov*.5)/(180*math.pi)))
            self.prerspective = np.array([[self.a*self.f,0,0,0],[0,self.f,0,0],[0,0,(self.far/(self.far-self.near)),1], [0,0,(self.far*self.near)/(self.far-self.near),0]])
            self.scale = np.array([[self.sca,0,0,0], [0,self.sca,0,0], [0,0,self.sca,0], [0,0,0,1]])
            self.trans = np.array([[1,0,0,self.transx], [0,1,0,self.transy], [0,0,1,self.transz], [0,0,0,1]])
            self.rotationx = np.array([[1,0,0,0],[0,float(np.cos(self.anglex)),float(-np.sin(self.anglex)),0],[0,float(np.sin(self.anglex)),float(np.cos(self.anglex)),0],[0,0,0,1]])
            self.rotationy = np.array([[float(np.cos(self.angley)),0,float(np.sin(self.angley)),0],[0,1,0,0],[float(-np.sin(self.angley)),0,float(np.cos(self.angley)),0],[0,0,0,1]])
            self.rotationz = np.array([[float(np.cos(self.anglez)),float(-np.sin(self.anglez)),0,0],[float(np.sin(self.anglez)),float(np.cos(self.anglez)),0,0],[0,0,1,0],[0,0,0,1]])
            screen.fill((0, 0, 0))
            screen.lock()
            for a,b,c in self.faces:
                triangle = np.array([
                    self.cubm[a],
                    [[i] for i in self.cubm[b]],
                    [[i] for i in self.cubm[c]]
                ])
                transtri = np.array([
                    self.trans@self.rotationz@self.rotationy@self.rotationx@self.scale@triangle[0],
                    [self.trans@self.rotationz@self.rotationy@self.rotationx@self.scale@triangle[1]],
                    [self.trans@self.rotationz@self.rotationy@self.rotationx@self.scale@triangle[2]]
                ])
                line1x = transtri[1][0][0][0] - transtri[0][0][0][0]
                line1y = transtri[1][0][1][0] - transtri[0][0][1][0]
                line1z = transtri[1][0][2][0] - transtri[0][0][2][0]
                line2x = transtri[2][0][0][0] - transtri[0][0][0][0]
                line2y = transtri[2][0][1][0] - transtri[0][0][1][0]
                line2z = transtri[2][0][2][0] - transtri[0][0][2][0]
                normalx = line1y * line2z - line1z * line2y
                normaly = line1z * line2x - line1x * line2z
                normalz = line1x * line2y - line1y * line2x
                l = np.sqrt(normalx*normalx+normaly*normaly+normalz*normalz)
                normalx /= l
                normaly /= l
                normalz /= l
                if (normalx * (transtri[0][0][0][0] - self.camera[0]) +
                    normaly * (transtri[0][0][1][0] - self.camera[1]) +
                    normalz * (transtri[0][0][2][0] - self.camera[2]) < 0):
                    light = [0,0,-1]
                    l = np.sqrt(light[0]*light[0]+light[1]*light[1]+light[2]*light[2])
                    light[0] /= l
                    light[1] /= l
                    light[2] /= l
                    dp = normalx * light[0] + normaly * light[1] + normalz * light[2]
                    color = self.get_color(dp)
                    projected = np.array([
                        [self.prerspective@transtri[0]],
                        [self.prerspective@transtri[1]],
                        [self.prerspective@transtri[2]]
                    ])
                    fart = [[i[0] for i in projected[0][0][0]], [i[0] for i in projected[1][0][0]], [i[0] for i in projected[2][0][0]]]
                    pygame.draw.polygon(screen, color,[(fart[0][0]+250, fart[0][1]+250), (fart[1][0]+250, fart[1][1]+250), (fart[2][0]+250, fart[2][1]+250)])
            screen.unlock()
            pygame.display.update()
        pygame.quit()
    def get_color(self, colNum):
        rgbNum = abs(int(255 - ((1-colNum)*225.0)))
        return (rgbNum,rgbNum,rgbNum)

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
                    vertex = [float(line[index1:index2]), float(line[index2:index3]), float(line[index3:-1])]
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
#Canvas(cube, 500, 500)
Renderer()
