import pickle
from MaxMods.Matrix import *
from MaxMods.Canvas import *
import keyboard as key
import math
import sys
import cupy as np
import numpy as AHH
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
        file = ObjLoader('3DRender/Cube.obj')
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
        file = ObjLoader('3DRender/Cube.obj')
        self.cubm = file.vertices
        self.faces = file.faces
        self.anglex = 0
        self.angley = 0
        self.anglez = 0
        self.sca = 2
        self.transx = 0
        self.transy = 0
        self.transz = 533
        self.fov = 90
        self.near = .01
        self.far = 1080000
        self.a = 500/500
        self.camera = [0,0,0]
        self.lookdir = [0,0,1]
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
            if key.is_pressed('up') is True:
                self.camera[1] += 1
            if key.is_pressed('down') is True:
                self.camera[1] -= 1
            if key.is_pressed('right') is True:
                self.camera[0] -= 1
            if key.is_pressed('left') is True:
                self.camera[0] += 1
            self.f = AHH.divide(1,(AHH.tan(AHH.divide(AHH.multiply(self.fov,.5),AHH.multiply(180,AHH.pi)))))
            prerspective1 = AHH.array([[AHH.multiply(self.a,self.f),0,0,0],[0,float(self.f),0,0],[0,0,AHH.divide(self.far,AHH.subtract(self.far,self.near)),1], [0,0,AHH.divide(AHH.multiply(self.far,self.near),AHH.subtract(self.far,self.near)),0]])
            prerspective = np._core.core.array(prerspective1)
            scale = np.array([[self.sca,0,0,0], [0,self.sca,0,0], [0,0,self.sca,0], [0,0,0,1]])
            trans = np.array([[1,0,0,self.transx], [0,1,0,self.transy], [0,0,1,self.transz], [0,0,0,1]])
            rotationx = np.array([[1,0,0,0],[0,float(np.cos(self.anglex)),float(-np.sin(self.anglex)),0],[0,float(np.sin(self.anglex)),float(np.cos(self.anglex)),0],[0,0,0,1]])
            rotationy = np.array([[float(np.cos(self.angley)),0,float(np.sin(self.angley)),0],[0,1,0,0],[float(-np.sin(self.angley)),0,float(np.cos(self.angley)),0],[0,0,0,1]])
            rotationz = np.array([[float(np.cos(self.anglez)),float(-np.sin(self.anglez)),0,0],[float(np.sin(self.anglez)),float(np.cos(self.anglez)),0,0],[0,0,1,0],[0,0,0,1]])
            self.up = np.array([0,-1,0])
            target = np.add(np.array(self.camera), np.array(self.lookdir))
            forward = np.subtract(np.array(target), np.array(self.camera))
            nforward = forward/np.linalg.norm(forward)
            up = np.subtract(self.up, np.multiply(nforward, np.dot(self.up, nforward)))
            nup = up/np.linalg.norm(up)
            nright = np.cross(nup, nforward)
            pointmat = np.array([np.append(nright, target[0]), np.append(nup, target[1]), np.append(nforward, target[2]), np.array([0,0,0,1])])
            viewmat = np.linalg.inv(pointmat)
            screen.fill((0, 0, 0))
            faces = []
            for a,b,c in self.faces:
                triangle = np.array([
                    self.cubm[a],
                    self.cubm[b],
                    self.cubm[c]
                ])
                transtri = np.array([
                    viewmat@trans@rotationz@rotationy@rotationx@scale@triangle[0],
                    viewmat@trans@rotationz@rotationy@rotationx@scale@triangle[1],
                    viewmat@trans@rotationz@rotationy@rotationx@scale@triangle[2]
                ])
                cross = np.cross(np.subtract(transtri[1], transtri[0])[:-1], np.subtract(transtri[2], transtri[0])[:-1])
                normal = cross/np.linalg.norm(cross)
                if (normal[0] * (transtri[0][0] - self.camera[0]) +
                    normal[1] * (transtri[0][1] - self.camera[1]) +
                    normal[2] * (transtri[0][2] - self.camera[2]) <= 0):
                    light = [0,0,1]
                    nlight = np.array(light)/np.linalg.norm(np.array(light))
                    dp = np.dot(normal, nlight)
                    color = self.get_color(dp)
                    projected = np.array([
                        prerspective@transtri[0],
                        prerspective@transtri[1],
                        prerspective@transtri[2]
                    ])
                    faces.append(((projected,color), (transtri[0][2]+transtri[1][2]+transtri[2][2])/3))
            screen.lock()
            faces.sort(key=self.sorttttt)
            faces.reverse()
            for (item,color),_ in faces:
                pygame.draw.polygon(screen, color, [i[:-2] for i in np.add(item, 250).tolist()])
            screen.unlock()
            pygame.display.update()
        pygame.quit()
    def get_color(self, colNum):
        rgbNum = abs(int(255 - ((1-colNum)*255.0)))
        return (rgbNum,rgbNum,rgbNum)
    def sorttttt(self, n):
        a,z = n
        return z
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
