# evrproxy - Tracing Proxy for EchoVR Protocol

# Prerequisites

Clone `https://github.com/echotools/nakama` and use `replace` in `go.mod`. See `go.mod`)

# Building

```sh

make
```

# Include Lists

The include list may be anything that `evr.ToSymbol(v any)` can process (e.g. snsloginrequestv2, 0xbdb41ea9e67b200a...)


`includes.txt`:

```text
SNSGenericMessage
SNSLoginRequestv2

```

# Example Usage

This runs in "TAP" mode (packet capture), decoding connections to the server on port 80.

```sh


# BOT URL https://discord.com/api/oauth2/authorize?client_id=1222219524481486868&permissions=947912767568&scope=bot%20applications.commands

# can use the environment or the command line for the bot token

export DISCORD_BOT_TOKEN="MTIyMjIxOTUyDEADBEEFg2OA.G2rGfg.g9wsLc-9sdI6Vdl_DEADBEEF8KB7-gSU8wK6ns"
export DISCORD_BOT_CHANNEL="1210510493471477842"

go run ./main.go \
     --bot-token "MTIyMjIxOTUyDEADBEEFg2OA.G2rGfg.g9wsLc-9sdI6Vdl_DEADBEEF8KB7-gSU8wK6ns" \
     --bot-channel "1210510493471477842" \
     --include-from=./includes.txt \
     --mode tap
     --msg-encoding yaml
     --ip 61.61.61.61
     --port 80

```
