import Auth
log = Auth.Auth('https://localhost:5679/')
log.Name = str(input('username: '))
log.Pass = str(input('password: '))
yeah = str(input('l or s: '))
if yeah == 'l':
    print(log.Login())
elif yeah == 's':
    print(log.Signup())
#except Auth.UsernameError as err:
   # if str(err) == 'Username already exists':
        #log.Login()
    #else: raise Auth.UsernameError(err)
#log._Auth__User = 'MAX'
#log.Save(['brug'], 'this data is encrypted')
#print(log.Load(['brug']))
