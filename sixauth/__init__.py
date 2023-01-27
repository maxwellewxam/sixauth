'''An all-in-one user authenticator and data manager'''
from .auth import *
__all__ = ['LocationError', 'AuthenticationError', 'UsernameError', 'PasswordError', 'DataError','AuthSesh']