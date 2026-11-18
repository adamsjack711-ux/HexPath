FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates nmap openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /root/.ssh \
    && chmod 0700 /root/.ssh

COPY entrypoint.sh /usr/local/bin/hexpath-jump-entrypoint

EXPOSE 22

ENTRYPOINT ["/usr/local/bin/hexpath-jump-entrypoint"]
