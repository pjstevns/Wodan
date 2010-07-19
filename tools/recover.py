#!/usr/bin/env python



import os

def createFileList(dirname):
	fileList = os.listdir(dirname)
	cflist = []
	for filename in fileList:
		filename = os.path.join(dirname, filename)
		if os.path.isdir(filename):
			cflist += createFileList(filename)
		else:
			cflist.append(filename)
	
	return cflist


def recover(cachedir, recoverdir):
    cachefiles = createFileList(cachedir)
    for cachefilename in cachefiles:
        print cachefilename
        cachefile = open(cachefilename, 'r')
        path = cachefile.readline().strip()
        if path[0] == '/':
            path = path[1:]

        dir = os.path.join(recoverdir, os.path.split(path)[0])
        try:
            os.makedirs(dir)
        except OSError:
            pass

        if path[-1] == '/':
            path = os.path.join(path,'index.html')
        path = os.path.join(recoverdir, path)

        print path
        newfile = open(path, 'w')

        # go past headers:
        while 1:
            line = cachefile.readline()
            if line == '\r\n' or line == '\n':
                break
        # copy file
        readbytes = cachefile.read()
        newfile.write(readbytes)

        cachefile.close()
        newfile.close()

if __name__ == '__main__':
    import sys
    def usage():
        print "recover.py <cachedir> <recoverydir>"
        sys.exit(1)
    try:
        c = sys.argv[1]
        r = sys.argv[2]
    except IndexError:
        usage()

    recover(c,r)

	
	
	
	
