all:
	python gen.py orig.c chall.c
	gcc -no-pie chall.c -o chall
	cp chall ../distfiles/chall
test:
	echo 'zer0pts{sc4110p_1s_my_m05t_fav0r1t3_su5h1_1t3m}' | ../distfiles/chall
clean:
	rm -f chall.c chall ../distfiles/chall
	