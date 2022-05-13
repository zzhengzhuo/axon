FROM ubuntu:20.04
WORKDIR /app

RUN apt-get update
RUN apt install -y libssl-dev
RUN apt install -y libc6-dev

CMD /app/build/axon  

