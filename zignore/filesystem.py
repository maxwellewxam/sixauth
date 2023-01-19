# in this file i am going to make a locked file browser
# this will be in the temp folder untill im done making it then i will move it
 
# ok this code is used to import max mods without having to to pip install it
# only because im developing maxmods and dont have it pip installed
import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)

# everything normal from here
from maxmods.auth import AuthSesh, AuthenticationError
import PySimpleGUI as sg

def parse_dict(d):
    if not d:
        return None
    dict_keys = []
    other_keys = []
    for key, value in d.items():
        if isinstance(value, dict):
            dict_keys.append(key)
        else:
            other_keys.append(key)
    return dict_keys, other_keys


def layout1():
    return [[sg.Text('Username'), sg.Input(key='username')],
            [sg.Text('Password'), sg.Input(password_char='*', key='password')],
            [sg.Button('Login'), sg.Button('Signup')],
            [sg.Text("", key="status_text")]]

def layout2(data={'a': 1, 'b': {'c': 2}, 'd': [3, 4], 'e': '5'}):
    layout = [[sg.Button('Logout'), sg.Button('New File'), sg.Button('New Folder'), sg.Button('Back')], [sg.Text('Name', auto_size_text=False, size=20), sg.Text('Type', auto_size_text=False, size=5)]]
    if parse_dict(data) != None:
        folders, files = parse_dict(data)
        for folder in folders:
            row = [sg.Text(f'{folder}', auto_size_text=False, size=20), sg.Text('Folder', auto_size_text=False, size=5), sg.Button('Open', key=f'Open|Folder|{folder}'), sg.Button('Delete', key=f'Delete|{folder}')]
            layout.append(row)
        for file in files:
            row = [sg.Text(f'{file}', auto_size_text=False, size=20), sg.Text('File', auto_size_text=False, size=5), sg.Button('Open', key=f'Open|File|{file}'), sg.Button('Delete', key=f'Open|{file}')]
            layout.append(row)
    else:
        layout.append([sg.Text('Empty')])
    return layout

def make_window(layout):
    win = sg.Window('Login', layout, location=(2800, 200))
    win.finalize()
    return win

window = make_window(layout2())
ash = AuthSesh()

while True:
    event, values = window.read()
    print(event, values)
    if event in (sg.WINDOW_CLOSED, 'Exit'):
        ash.terminate()
        break
    if event.startswith('Open'):
        print('oops')
    
    if event.startswith('Delete'):
        print('deleted')
    
    if event == "Login":
        window["status_text"].update("Logging in...")
        ash.set_vals(values['username'], values['password'])
        try:
            ash.login()
        except AuthenticationError as err:
            window["status_text"].update(str(err))
        else:
            window.close()
            #print(layout2(ash.load()))
            window = make_window(layout2())
    
    if event == "Signup":
        window["status_text"].update("Signing up...")
        ash.set_vals(values['username'], values['password'])
        try:
            ash.signup()
            ash.login()
        except AuthenticationError as err:
            window["status_text"].update(str(err))
        else:
            window.close()
            window = make_window(layout2())
    
    if event == "Logout":
        pass
window.close()