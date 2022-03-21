FROM sagemath/sagemath:latest

WORKDIR /
USER root

RUN sage -python -m pip install pycryptodome

ADD ./solve.sage solve.sage

ENTRYPOINT sage solve.sage
