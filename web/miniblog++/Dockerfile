FROM tiangolo/uwsgi-nginx-flask:python3.8

RUN apt update
RUN groupadd -r ctf && useradd -r -g ctf ctf
RUN pip install Flask pycryptodome

WORKDIR /home/ctf
ADD ./challenge/app.py    ./
ADD ./challenge/templates ./templates
ADD ./challenge/flag.txt  /flag-wowRCEwow.txt
ADD ./challenge/uwsgi.ini ./
RUN mkdir ./post
RUN chown -R root:ctf ./
RUN chmod -R 550      ./
RUN chown -R ctf:ctf  ./post
RUN chmod    330      ./post
