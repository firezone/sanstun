FROM ubuntu:24.04

COPY . /benches/

WORKDIR /tmp

# Bencher's Bare Metal runners stop a job after 5 minutes.
ENTRYPOINT ["sh", "-ec", "for bench in /benches/*; do \"$bench\" --bench --noplot --warm-up-time 1 --measurement-time 3; done"]
