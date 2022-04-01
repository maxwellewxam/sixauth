import Auth
log = Auth.Auth()
log.Name = str(input('username: '))
log.Pass = str(input('password: '))
#try:
print(log.Login())
#except Auth.UsernameError as err:
   # if str(err) == 'Username already exists':
        #log.Login()
    #else: raise Auth.UsernameError(err)
#log._Auth__User = 'MAX'
#log.Save(['brug'], 'this data is encrypted')
#print(log.Load(['brug']))
