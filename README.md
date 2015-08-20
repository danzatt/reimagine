# reimagine
This tool can be used for decrypting IMG files, listing, dumping their tags and patching their contents (using ibootsup from opensn0w-X).

**Licensed under GNU GPL.** 

```
Usage: reimagine <infile> [<outfile>] <options>

<options> are:
	-iv <IV>	set IV for decryption
	-k <key>	set key for decryption
	-d, --dump	print tag names and hexdump their content
			(Note: this option works on the final decrypted/patched file)
	-l, --list	list tags present in file
	-r, --raw	dump the DATA tag to <outfile>
	-p, --patch	patch the file using ibootsup
	-x, --decompress	decompress lzss compressed kernelcache

Copyright 2015, danzatt <twitter.com/danzatt>
You should have received a copy of the GNU General Public License and source code along with this program. If you haven't, you should ask your source to provide one.

Thanks to winocm for opensn0w-X, guys behind xpwntool and decodeimg3.pl for decryption logic, J from newosxbook.com for device tree headers.

```

#Example usage
* Pwned iBEC for kloader
`reimagine iBEC.n90ap.RELEASE.dfu -k ... -iv ... -p -r`
* Pwned iBoot for iBEC
`reimagine iBoot.n90ap.RELEASE.img3 -k ... -iv ... -p`
* Decrypt kernel and extract into MachO file
`reimagine kernelcache.release.n90 kernel.macho -iv ... -k ... -x -r`

#Building
You need 32bit OpenSSL (e.g. `sudo apt-get install libssl-dev:i386`).  
`git clone --recursive https://github.com/danzatt/reimagine.git`  
`cd reimagine/opensn0w-X/src && make all`  
`cd ../.. && make`
