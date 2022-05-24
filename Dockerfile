FROM ubuntu:20.04
WORKDIR /app

RUN rm /var/lib/apt/lists/* -fv
RUN apt-get update
RUN apt install -y libssl-dev
RUN apt install -y libc6-dev
RUN apt-get -y install ca-certificates

CMD /app/build/axon  

