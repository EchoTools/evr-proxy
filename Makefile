BUILD := `git describe --dirty=+ --tags --always`
LDFLAGS=-ldflags "-X=$(GIT)build.Build=$(BUILD)"
all: evrproxy

evrproxy: main.go
	echo $(BUILD)
	go build -v $(LDFLAGS) -o evrproxy main.go

