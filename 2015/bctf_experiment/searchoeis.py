from sage.all import *
import sys


def main():
    c = oeis(sys.argv[1])[0]
    print c.id()

if __name__ == "__main__":
    main()
