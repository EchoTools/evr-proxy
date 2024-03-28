

all: evrproxy

evrproxy: main.go
	go build -o evrproxy main.go

