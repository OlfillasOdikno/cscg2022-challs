# docker build -t backdoor . && docker run --rm -it -p1024:1024 backdoor
# ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no ctf@127.0.0.1 -p 1024
FROM ubuntu@sha256:a02c32cf0c2a7e8743c74deef66637aa70e063c9bd40e9e1f8c0b3ea0750b0ba

RUN apt-get update && apt-get install -y dropbear rsync openssh-client && apt-get clean # openssh-client provides scp

COPY flag /flag
RUN chmod 600 /flag
COPY ping /bin/ping
RUN chmod u+s /bin/ping
RUN useradd -d /home/ctf/ -m -s /bin/bash ctf && passwd -d ctf

WORKDIR /home/ctf

CMD ["dropbear", "-FBREkwp", "1024"]
