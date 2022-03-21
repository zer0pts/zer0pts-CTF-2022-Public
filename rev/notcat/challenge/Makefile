DIR:=$(shell pwd)

all:
	haxe build.hxml
	cd /home/ptr/armoury/hashlink; ./hl $(DIR)/test.hl $(DIR)/flag.txt
