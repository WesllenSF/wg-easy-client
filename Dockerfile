FROM alpine:3.20

# python3: servidor web (só biblioteca padrão, sem pip)
# wireguard-tools: wg e wg-quick; iptables: kill-switch
RUN apk add --no-cache python3 wireguard-tools iptables ip6tables iproute2 bash \
 # o contêiner não pode gravar em /proc/sys: só chama o sysctl se o valor ainda não for 1
 && sed -i 's|\[\[ \$proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1|[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1|' /usr/bin/wg-quick \
 && grep -q 'sysctl -n net.ipv4.conf.all.src_valid_mark' /usr/bin/wg-quick \
 # partes da biblioteca padrão que nunca são usadas
 && rm -rf /usr/lib/python3*/ensurepip /usr/lib/python3*/idlelib /usr/lib/python3*/lib2to3 \
           /usr/lib/python3*/pydoc_data /usr/lib/python3*/tkinter /usr/lib/python3*/turtledemo

COPY rootfs/ /
COPY app/ /app/
RUN chmod 755 /usr/local/sbin/resolvconf && python3 -m compileall -q /app

ENV WGEC_DATA=/config \
    WGEC_PORT=51821 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

VOLUME /config
EXPOSE 51821/tcp
STOPSIGNAL SIGTERM
CMD ["python3", "/app/server.py"]
