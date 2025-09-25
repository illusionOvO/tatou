import hashlib

flag1 = hashlib.sha1(b"randomstring1").hexdigest()
flag2 = hashlib.sha1(b"randomstring2").hexdigest()
flag3 = hashlib.sha1(b"randomstring3").hexdigest()

print("Flag1: ",flag1)
print("Flag2: ",flag2)
print("Flag3: ",flag3)