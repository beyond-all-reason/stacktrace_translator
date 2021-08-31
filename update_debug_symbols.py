import os, sys
import tarfile

def runcmd(cmd):
	print ("running cmd:", cmd)
	os.system(cmd)


def extract(tar_url, extract_path='.'):
	print tar_url
	tar = tarfile.open(tar_url, 'r')
	for item in tar:
		print ("item name", item.name)
		if item.name == "./spring.dbg" or item.name.startswith( "./AI"):
			tar.extract(item, extract_path)
			print ("Extracted spring.dbg", extract_path)
		if item.name.find(".tgz") != -1 or item.name.find(".tar") != -1:
			extract(item.name, "./" + item.name[:item.name.rfind('/')])
			
print ("Pass the parameter to the output of the github actions windows debug build as a command line arg to this script")
archiveurl = sys.argv[1]
symboltgz = archiveurl.rpartition("/")[2]

engine_version = '104.' + symboltgz.rpartition("_windows")[0].partition("104.")[2]
targetdir = "default/" + engine_version
# https://github.com/beyond-all-reason/spring/releases/download/spring_bar_%7BBAR%7D104.0.1-1977-g12700e0/spring_bar_.BAR.104.0.1-1977-g12700e0_windows-64-minimal-symbols.tgz

print(archiveurl,symboltgz, engine_version)
runcmd("wget " + " " + archiveurl)

print(archiveurl,symboltgz, engine_version)
runcmd("mkdir default")
runcmd("mkdir " + targetdir)

for filename in os.listdir(os.getcwd()):
	if engine_version in filename and filename.endswith(".tgz"):
		extract(filename)

runcmd ("rm spring_dbg.7z")
runcmd ("7za a spring_dbg.7z spring.dbg ./AI")
runcmd ("mv spring_dbg.7z ./"+targetdir+'/')

runcmd ("rm -r ./AI") 
runcmd ("rm spring.dbg")
runcmd ("rm "+symboltgz)
