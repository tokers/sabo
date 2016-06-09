import collections
import sys
while True:
    l = [int(x) for x in input().split()]
    if l != []:
        print(sum(l))
    else:
        break
