from math import sqrt
import time
s=time.time()
num=1
pcnt=0
def prime(n):
    sqroot=int(sqrt(n))
    j=2
    while j<=sqroot:
        if n%j==0:
            return False
        j=j+1
    return True

s = time.time()
prime(23338198).__repr__()
print time.time()-s