
import PyDes as D

D.Init()

text = "abcdefghijklnmopqrstuvwxyzABCDEFGHIJKLNMOPQRSTUVWXYZ0123456789"
print text, type(text), len(text)

crypt = D.Encrypt(text)
print crypt, type(crypt), len(crypt)

plain = D.Decrypt(crypt)
print plain, type(plain), len(plain)

assert(text == plain)
