FROM golang:1.21

WORKDIR /gosnake

COPY . .

RUN cd cmd/gosnake-auto && go build -o gosnake-auto

#CMD ["/gosnake/cmd/gosnake-auto/gosnake-auto", "-c=/gosnake/cmd/gosnake-auto/config.yaml"]