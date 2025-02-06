FROM ubuntu:noble

RUN apt update && apt install -y iproute2 net-tools adduser nano

CMD ["/bin/bash", "-c", "trap : TERM INT; sleep infinity & wait"]
