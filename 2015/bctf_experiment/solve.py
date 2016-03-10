import os
import re
import socket
import math
from sage.all import *
import time
import urllib2
import urllib


HOST = '104.197.7.111'
PORT = 13135

rex = re.compile("Is (.*) an (.*) or not")
rex_op = re.compile("[^0-9\\/\+\-\*\.]")

resp = {
    True: 'yes',
    False: 'no',
}


def get_big_prime(n):
    url = "http://primes.utm.edu/nthprime/index.php"
    values = {'n': n}
    data = urllib.urlencode(values)
    headers = {"referer": "http://primes.utm.edu/nthprime/index.php"}
    req = urllib2.Request(url, data, headers)
    response = urllib2.urlopen(req)
    the_page = response.read()
    result = re.findall("The [0-9,]*.* prime is ([0-9,]*)", the_page)[0]
    return result

def powLF(n):
    if n == 1:
        return (1, 1)
    L, F = powLF(n // 2)
    L, F = (L**2 + 5 * F**2) >> 1, L * F
    if n & 1:
        return ((L + 5 * F) >> 1, (L + F) >> 1)
    else:
        return (L, F)


def fib(n):
    if n & 1:
        return powLF(n)[1]
    else:
        L, F = powLF(n // 2)
        return L * F


def get_prime(n):
    i = 0
    num = 2
    while(i < n):
        if all(num % i != 0 for i in range(2, int(math.sqrt(num)) + 1)):
            i += 1
        num += 1
    return num - 1


def unlabeled_nodes(n):
    fp = open("b000055.txt", "r")
    for i in range(0, n + 1):
        n = fp.readline()
        num = int(n.split(" ")[1])
    fp.close()

    return num


def recvuntil(s, eol="\n"):
    out = ""
    while(1):
        b = s.recv(1)
        if eol in b:
            break
        if "Your answer looks too strange... No flag for you." in b:
            exit()

        out += b
    return out

def recvline(s):
    out = recvuntil(s)
    if out == "" or out == " " or out == "\n" or out is None:
        out = recvline(s)
    return out


def getfromtable(oeis, n):
    _id = oeis.id()
    _id = _id.split("A")[1]
    tab = "b%s.txt" % _id
    url = oeis.url() + "/" + tab
    # print "getting %s\n" % url
    response = urllib2.urlopen(url)

    for line in response:
        if "#" not in line:
            (i, result) = [int(k) for k in line.split(" ")]
            if i == n:
                return result
    return None


def main():

    answered = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    q = s.recv(2048)
    print q

    while(1):

        q = s.recv(2048)
        print q
        if "uh... Thank you! That's all." in q:
            exit()
        elif "Great! Time for calculating weird integer sequences." in q:
            break

        (op, _type) = rex.findall(q)[0]
        if rex_op.match(op):
            result = 1.5
        else:
            result = float(eval(op))
        print result

        s.sendall(resp[result.is_integer()] + "\n")
        answered += 1

    # prime numbers sequence
    q = s.recv(2048)
    print q
    n = re.findall("n = ([0-9]*),", q)[0]
    n = int(n)

    result = get_prime(int(n))
    s.sendall("%d\n" % result)
    answered += 1

    q = s.recv(4098)
    print q
    q = s.recv(4098)
    print q
    n = re.findall("n = ([0-9]*),", q)[0]
    n = int(n)

    result = fib(n)
    print result
    s.sendall("%d\n" % result)
    answered += 1

    q = s.recv(4098)
    print q
    q = s.recv(4098)
    print q
    n = re.findall("n = ([0-9]*),", q)[0]
    n = int(n)

    result = unlabeled_nodes(n)
    print result
    s.sendall("%d\n" % result)
    answered += 1

    while(1):
        print "(%d)" % answered
        time.sleep(0.2)
        primes = False
        # searching oeis database
        q = recvline(s)
        time.sleep(0.2)
        print q
        if "Last few ones, I promise." in q:
            q = recvline(s)
            time.sleep(0.2)
            print q

        description = q.split("Description: ")[1].strip()

        if "The Prime Numbers Revenge" in description:
            primes = True

        time.sleep(0.2)
        q = recvline(s)
        print q
        if "Answer" in q:
            sequence = None
        else:
            sequence = q.split("The sequence starts with: ")[1]
            # sequence = [int(n) for n in sequence.split(",")]
            time.sleep(0.2)
            q = recvline(s)
            time.sleep(0.2)
            print q

        q = s.recv(2048)
        time.sleep(0.2)
        print q
        n = re.findall("n = ([0-9]*),", q)[0].strip()
        n = int(n)

        if primes:
            # http://primes.utm.edu/nthprime/
            print "\nsearch and insert result!"
            result = int(get_big_prime(n))
            print result
            s.sendall("%d\n" % result)
            answered += 1
            continue

        if answered == 46:
            result = catalan_number(n)
            print result
            s.sendall("%d\n" % result)
            answered += 1

        if answered == 47:
            d = 4.189610958393826965527036454524
            c = 0.35683683547585
            result = c * d^n / n^(3/2)
            print result
            result = int(result)
            s.sendall("%d\n" % result)
            answered += 1

        try:
            c = oeis(sequence + " " + ("\"%s\"" % description))[0]
        except:
            try:
                c = oeis(sequence + " " + description)[0]
            except:
                if len(sequence) > 4:
                    c = oeis(sequence)[0]
                else:
                    try:
                        c = oeis(("\"%s\"" % description))[0]
                    except:
                        try:
                            c = oeis(description)[0]
                        except:
                            c = c = oeis(description[0:45])[0]

        try:
            result = c(n)
        except Exception as e:
            try:
                result = getfromtable(c, n)
            except:
                print "\nsearch and insert result!"
                result = int(raw_input())

        print result
        s.sendall("%d\n" % result)
        answered += 1

    s.close()

if __name__ == "__main__":
    main()
