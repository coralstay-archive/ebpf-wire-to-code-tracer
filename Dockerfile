FROM rockylinux:9

RUN dnf install -y \
    clang \
    llvm \
    gcc-c++ \
    make \
    binutils \
    elfutils-libelf-devel \
    python3 \
    python3-pip \
    graphviz \
    iproute \
    && dnf clean all

RUN pip3 install --no-cache-dir pytest pyelftools

WORKDIR /workspace
COPY . /workspace

RUN chmod +x /workspace/test_harness.sh

EXPOSE 8080 8090

CMD ["/workspace/test_harness.sh"]
