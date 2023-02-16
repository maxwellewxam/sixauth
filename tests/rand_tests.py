

# message to self, we are gonna store the ivs into a file called ivs.txt, we will decrypt the file and laod it in when a new session is made
# we will encrypt it when close session is called. ivs will be a dictionary of usernames -> iv. we will use the fast cryption funcs from main and 
# store this file in the same place as the database, maybe look into finding a way to make a table of username to iv in our current database file
