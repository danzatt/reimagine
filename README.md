# reimagine
This tool can be used for decrypting IMG files, listing, dumping their tags and patching their contents (using ibootsup from opensn0w-X).
```
Usage: reimagine <infile> <outfile> -iv <IV> -k <key>

Other options are:
	-d, --dump	print tag names and hexdump their content
			(Note: this option works on the final decrypted/patched file)
	-l, --list	list tag present in file
	-r, --raw	dump the DATA tag to <outfile>
	-p, --patch	patch the file using ibootsup
```
#Building
`git clone --recursive git@github.com:danzatt/reimagine.git`  
`cd reimagine/opensn0w-X/src && make all`  
`cd ../.. && make`
