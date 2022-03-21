#!/bin/sh
docker run --rm --network=none --name readflag -it readflag \
       timeout -s9 300 bash
