FROM alpine:3.14
RUN apk add --no-cache qemu-system-i386 python3 qemu-ui-curses
COPY . /work
WORKDIR /work
ENV TERM=xterm
ENV FLAG1="CSCG{flag1}"
ENV FLAG2="CSCG{flag2}"
ENV FLAG3='CSCG{flag3}'

ENTRYPOINT ["python3", "/work/server.py"]
#docker build -t secureboot .
#docker run -t --rm -p1024:1024 secureboot
#use this for graphical, there will be no output until curses kicks in: socat file:`tty`,raw,echo=0 tcp:localhost:1024
#else do: nc localhost 1024
#I recommend interacting with pwntools