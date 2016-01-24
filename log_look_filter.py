#/usr/bin/env python
# POSSIBLE PROBLEM WITH THIS IS BLOCKING WHOLE IP FROM COMMUNICATING
# SO A BAD LOGIN WILL BLOCK EVERY SERVICE, GOOD AND BAD POSSIBILITIES
keylist=['root','user',"for"]
import re
import sys
import time
import string
#from subprocess import call
import os
table_unblock=["iptables","-D","INPUT","1"]
table_look=["iptables","-L","INPUT","-v","-n"]

logflook = open('/var/log/secure', 'r')

def process(thisline,blockit):
	keyfound= False
	print "-----process----"
        for word in keylist:
                splitline = thisline.split()
		print splitline
                if word in splitline:
			print word
                        if word == 'root':
                                word_index=splitline.index("root")
				keyfound=True
                        if word == 'user':
                                word_index=splitline.index("user")+1
				keyfound=True
                        if word == 'for':
                                word_index=splitline.index("for")+1
				keyfound=True
                        if word == 'from':
                                word_index=splitline.index("from")+1
				keyfound=True
                        print splitline[0:3],
                        print splitline[word_index],
                        print splitline[word_index+2:word_index+3]
                        if (blockit & keyfound):
                                block_raw = splitline[word_index+2]
				block=block_raw.translate(string.maketrans('',''),"::ffff:")
				print splitline
                                print splitline[word_index+2]
                                execute=" ".join(["iptables","-I","INPUT","-s",block,"-p","tcp","--dport","22","-j","REJECT"])
				print execute
				os.system(execute)
                                #Block ssh login from IP for 60 seconds
                                for counter in range(1,20):
					print splitline
                                        os.system(" ".join(table_look))
                                        time.sleep(3)
                                os.system(" ".join(table_unblock))
                                os.system(" ".join(table_look))
                                print block
                        sys.stdout.flush()

#Define block line as the last bad line, to avoid blocking IP's only in past history, not current.
keep_going = True
block_line = ''
block=''
while keep_going:
        lastline = logflook.readline()
        # current end of file
        if lastline == '':
                #keep_going=False
                if(block_line != ''):
                        process(block_line,True)
                        #we took care of it, don't keep doing it
                        block_line=''
                #give the system a short break between reading at the end of file
                time.sleep(0.1)
        if re.search("Failed password for", lastline):
		#print(lastline)
                block_line=lastline


