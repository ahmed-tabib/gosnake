FROM golang:1.21

WORKDIR /gosnake

COPY . .

# Build gosnake-auto and create symlink
RUN cd cmd/gosnake-auto && go build -o gosnake-auto && ln -s /gosnake/cmd/gosnake-auto/gosnake-auto /usr/bin
# Create config file dir and copy it there
RUN cd cmd/gosnake-auto && mkdir /etc/gosnake-auto && cp config.yaml /etc/gosnake-auto

# Run Gosnake
CMD ["gosnake-auto", "-c=/etc/gosnake-auto/config.yaml"]