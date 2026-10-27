FROM ubuntu:26.04

ARG USERNAME=dev
ARG USER_UID=1000
ARG USER_GID=$USER_UID
ENV DEBIAN_FRONTEND=noninteractive

# System packages only; runtimes (uv, Node, JDK, .NET) are installed into
# .runtime/ by platforms/linux/bootstrap.sh in postCreateCommand.
COPY platforms/linux/apt-packages.txt /tmp/apt-packages.txt
RUN apt-get update \
    && sed -e 's/#.*//' -e '/^[[:space:]]*$/d' /tmp/apt-packages.txt \
       | xargs apt-get install -y --no-install-recommends \
         python3 direnv sudo bash-completion \
    && rm -rf /var/lib/apt/lists/* /tmp/apt-packages.txt

# ubuntu images ship a uid 1000 "ubuntu" user; replace it with $USERNAME
RUN (userdel -r ubuntu 2>/dev/null || true) \
    && groupadd --gid "$USER_GID" "$USERNAME" \
    && useradd --uid "$USER_UID" --gid "$USER_GID" -m -s /bin/bash "$USERNAME" \
    && echo "$USERNAME ALL=(root) NOPASSWD:ALL" > "/etc/sudoers.d/$USERNAME"

USER $USERNAME
RUN echo 'eval "$(direnv hook bash)"' >> ~/.bashrc
