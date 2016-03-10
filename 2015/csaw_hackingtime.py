from z3 import *

table1 = [0x70, 0x30, 0x53, 0xA1, 0xD3, 0x70, 0x3F, 0x64, 0xB3, 0x16,
          0xE4, 0x04, 0x5F, 0x3A, 0xEE, 0x42, 0xB1, 0xA1, 0x37, 0x15,
          0x6E, 0x88, 0x2A, 0xAB]
table2 = [0x20, 0xAC, 0x7A, 0x25, 0xD7, 0x9C, 0xC2, 0x1D, 0x58, 0xD0,
          0x13, 0x25, 0x96, 0x6A, 0xDC, 0x7E, 0x2E, 0xB4, 0xB4, 0x10,
          0xCB, 0x1D, 0xC2, 0x66, 0x3B]

s = Solver()

Serial = [BitVec('serial%s' % i, 8) for i in range(len(table1))]  # serial

byte_3b = BitVec('byte3b', 8)

stack = []

s = Solver()

Y = 0

s.add(byte_3b == 0)  # set initial state for byte_3b

# state = byte_3b  # this is the sum of states for the byte 3b when we go on


def is_alphanum(x):
    return Or(
        And(x >= 0x30, x <= 0x39),
        And(x >= 0x41, x <= 0x5a),
        x == 0x20)
    # And(x >= 0x61, x <= 0x7a)


def display_model(m):
    block = {}
    password = ""
    for x in m:
        if 'serial' in str(x):
            block[int(str(x)[6:])] = int(str(m[x]))

    for v in block.itervalues():
        password += chr(v)

    print password

while Y < 24:
    cond = is_alphanum(Serial[Y])

    s.add(cond)
    A = Serial[Y]
    A = RotateLeft(A, 3)

    byte_3b = RotateRight(byte_3b, 2)
    A += byte_3b
    A ^= table1[Y]
    byte_3b = A

    A = RotateLeft(A, 4)
    A ^= table2[Y]

    s.add(A == 0)
    Y += 1

if s.check() == sat:
    m = s.model()
    display_model(m)
else:
    print 'no solution found!!'
