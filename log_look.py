#/usr/bin/env python
keylist=['root','user']
import re
import sys
import time

logflook = open('/var/log/secure', 'r')

def process(thisline):
        for word in keylist:
                splitline = thisline.split()
                if word in splitline:
                        if word == 'root':
                                word_index=splitline.index("root")
                        if word == 'user':
                                word_index=splitline.index("user")+1
                        print splitline[word_index],
                        print splitline[word_index+2:word_index+3]

keep_going = True
while keep_going:
        logline = ''
        lastline = logflook.readline()
        if lastline == '':
                keep_going=False
        if re.search("Failed password for", lastline):
                process(lastline)
