# syntax=docker/dockerfile:1.4

FROM archlinux/archlinux:base-devel-20230921.0.180222 as pkg-install
ENV PATH /usr/local/bin:$PATH
ENV LANG C.UTF-8

WORKDIR /opt

RUN --mount=type=cache,sharing=locked,target=/var/cache/pacman pacman-key --init && pacman --noconfirm --noprogressbar -Sy archlinux-keyring && pacman --noconfirm --noprogressbar --needed -Su git base-devel vim net-tools jq gcc rust openssl zsh grml-zsh-config zsh-lovers 


FROM pkg-install as build-environment
RUN [[ "$TARGETARCH" = "arm64" ]] && echo "export CFLAGS=-mno-outline-atomics" >> $HOME/.profile || true

WORKDIR /opt/dv
COPY . .

RUN --mount=type=cache,target=/root/.cargo/registry --mount=type=cache,target=/root/.cargo/git --mount=type=cache,target=/opt/dv/release \
    cargo clean \
    && cargo build --release \
    && mkdir out \
    && mv target/release/dv out/dv \
    && mv target/release/fetch-from-etherscan out/fetch-from-etherscan \
    && strip out/dv \
    && strip out/fetch-from-etherscan

FROM pkg-install as dv

COPY --from=build-environment /opt/dv/out/dv /usr/local/bin/dv
COPY --from=build-environment /opt/dv/out/fetch-from-etherscan /usr/local/bin/fetch-from-etherscan

RUN useradd -m -p123456 -u 1000 dv

USER dv
WORKDIR /home/dv

# Get foundryup
RUN export SHELL=/bin/zsh && curl -L https://foundry.paradigm.xyz | zsh
RUN ["/bin/zsh", "-c", "-i", "foundryup"]

ENTRYPOINT ["/bin/zsh"]


LABEL org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Deployment Validation"
