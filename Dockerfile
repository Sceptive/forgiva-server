FROM ubuntu:18.04

ARG VER

RUN ["/bin/bash", "-c", ": ${VER:?Version needs to be set to create container image.}"]

ENV WD=/opt/forgiva-server/

RUN addgroup forgiva
RUN adduser --disabled-password --disabled-login --gecos '' --home "$WD" --ingroup forgiva  fuser
RUN chown -R fuser:forgiva ${WD}

USER fuser

RUN mkdir -p ${WD}/bin

COPY \
    build/forgiva_server-${VER}-linux-x86_64-release \
    ${WD}/bin/forgiva-server


EXPOSE 3000

WORKDIR ${WD}
ENTRYPOINT ["/opt/forgiva-server/bin/forgiva-server"]

