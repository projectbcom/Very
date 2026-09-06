FROM sagemath/sagemath:9.5-ubuntu20.04

LABEL maintainer="malb"

USER root

RUN apt-get update && apt-get install -y git build-essential cmake libgmp-dev libmpfr-dev libfplll-dev

WORKDIR /bdd-predicate

COPY . /bdd-predicate

RUN source /opt/sagemath/sage-env && \
    pip3 install -r requirements.txt && \
    pip3 install black

RUN rm requirements.txt

ENTRYPOINT ["sage", "-python"]
