FROM sagemath/sagemath:latest

LABEL maintainer="malb"

WORKDIR /bdd-predicate

RUN apt-get update && apt-get install -y git

COPY . /bdd-predicate

RUN source "$SAGE_ROOT/local/bin/sage-env" && \
    pip3 install -r requirements.txt && \
    pip3 install black

RUN rm requirements.txt

ENTRYPOINT ["sage", "-python"]
