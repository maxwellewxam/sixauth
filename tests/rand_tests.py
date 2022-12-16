import sys
import os
HERE = os.path.abspath(os.getcwd())
sys.path.append(HERE)
from maxmods.menu import *
# Create a BasicMenu instance with the title "My Menu"
menu = BasicMenu("My Menu")

# Add some items to the menu
menu.add_item(1, "Option 1", print, "Option 1 selected")
menu.add_item(2, "Option 2", print, "Option 2 selected")
menu.add_item(3, "Option 3", print, "Option 3 selected")

# Run the menu
menu.run()