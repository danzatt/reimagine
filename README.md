# reimagine
This tool can be used for decrypting IMG files, listing, dumping their tags and patching their contents (using ibootsup from opensn0w-X).

**Licensed under GNU GPL.** 

```
Usage: reimagine <infile> [<outfile>]

Other options are:
	-iv <IV>	set IV for decryption
	-k <key>	set key for decryption
	-d, --dump	print tag names and hexdump their content
			(Note: this option works on the final decrypted/patched file)
	-l, --list	list tags present in file
	-r, --raw	dump the DATA tag to <outfile>
	-p, --patch	patch the file using ibootsup
	-x, --decompress	decompress lzss compressed kernelcache

```

#Example usage
* Pwned iBEC for kloader
`reimagine iBEC.n90ap.RELEASE.dfu -k ... -iv ... -p -r`
* Pwned iBoot for iBEC
`reimagine iBoot.n90ap.RELEASE.img3 -k ... -iv ...`
* Decrypt kernel and extract into MachO file
`reimagine kernelcache.release.n90 kernel.macho -iv ... -k ... -x -r`

#Building
`git clone --recursive git@github.com:danzatt/reimagine.git`  
`cd reimagine/opensn0w-X/src && make all`  
`cd ../.. && make`
