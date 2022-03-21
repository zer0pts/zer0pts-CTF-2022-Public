FROM debian:bullseye-slim

RUN echo '🐱:x:1337:1337:🐱:/:/bin/bash' >>/etc/passwd
RUN echo '🏴:x:1337:' >>/etc/group

ADD challenge/readflag /
RUN chmod 04111 /readflag

USER 1337:1337
