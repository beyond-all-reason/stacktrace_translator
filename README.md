# stacktrace_translator
This provides a web-based frontend for translating stack traces of SpringRTS engine crashes

# Updating debug symbols:

run update_debug_symbols.py with an URL to the zipped debug symbols archive from GH releases


# Installation:

Had to install:

sudo apt-get install php7.4-xmlrpc

Added info.php to get server info about xmlrpc


needed curl:
sudo apt-get install php7.4-curl


>> http://springrts.com:8000:Failed to connect to springrts.com port 8000: Connection refused

Needed to change paths in stacktrace_translator.py

Needed binutils:
sudo apt-get install binutils-mingw-w64-i686

Needs 7za:
sudo apt install p7zip-full

Needed to change :

$res['TRANSLATOR']="http://127.0.0.1:8000";


>>Error: :Unable to find detailed version in infolog
>>Maybe this stacktrace is from an self-compiled spring, or is the stack-trace to old?
This script only can handle >=0.82

New one: 
[t=00:02:04.350819][f=0000536] Error: Spring 104.0.1-1695-gbd6b256 BAR has crashed.
Actual engine path: engine\spring_bar_{BAR}104.0.1-1695-gbd6b256_windows-64-minimal-portable\
[t=00:02:04.492434][f=0000536] Error: 	(0) C:\Users\psarkozy\Documents\My Games\Spring\engine\spring_bar_{BAR}104.0.1-1695-gbd6b256_windows-64-minimal-portable\spring.exe [0x004DD130] 


The currently used regex looks like this:

https://jex.im/regulex/#!cmd=export&flags=&re=(%3F%3A%5BsS%5Dpring)%20%3F(%5B0-9%5D%2B%5C.%5B0-9%5D%2B%5B%5C.0-9%5D*(%3F%3A-%5B0-9%5D%2B-g%5B0-9a-f%5D%2B)%3F)%20%3F(%5Ba-zA-Z0-9%5C-%5D%2B)%3F%20%3F%3F(%3F%3A%5Cs*%5C((%3F%3A%5Ba-zA-Z0-9%5C-%5D%2B%5C)))%3F%5C.(%3F%3A%5B%5Cr%5Cn%5D%2B%24)%3F

(?:[sS]pring) ?([0-9]+\.[0-9]+[\.0-9]*(?:-[0-9]+-g[0-9a-f]+)?) ?([a-zA-Z0-9\-]+)? ??(?:\s*\((?:[a-zA-Z0-9\-]+\)))?\.(?:[\r\n]+$)?


The directories that debug symbols need to be placed into are: 
note that ~/www/www is symlinked to /var/www
/home/eru/www/www/bar/stacktrace_translator/default/104.0.1-1695-gbd6b256/BAR/win32
No debugging symbols available, "/home/eru/www/www/bar/stacktrace_translator/default/104.0.1-1695-gbd6b256/BAR/win32" not a directory

The debug symbols are packed tightly by ivand, thus need unzip, untargz, selection of proper .dbg file....

The regular sudo apt-get install binutils is needed for addr2line

# Running the XMLRPC service:

run stacktrace_translator.py an a separate shell session 

# Apache Conf:

Nothing special needed, set:

<Directory /var/www/>
	Options Indexes FollowSymLinks
	AllowOverride None
	Require all granted
</Directory>

if you store the archives symlinked

# TODO:

Turn the stacktrace_translator into a system service

