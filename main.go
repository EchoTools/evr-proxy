package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
	"github.com/gorilla/websocket"
	"github.com/heroiclabs/nakama/v3/server/evr"
	"github.com/joho/godotenv"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/yaml.v3"
)

const (
	Version  = "dev"
	Inbound  = "inbound"
	Outbound = "outbound"
)

// upgrader is used to upgrade the HTTP server connection to the WebSocket protocol.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Flags struct {
	port             int
	outputDir        string
	timestamp        bool
	setTitle         bool
	destination      string // host:port
	logPath          string
	debug            bool
	mode             string
	snaplen          int
	promisc          bool
	ip               string
	botChannel       string
	botToken         string
	msgFormat        string
	includeFrom      string
	excludeFrom      string
	include          string
	exclude          string
	rateLimit        int
	listSymbols      bool
	version          string
	savePacketData   bool
	decodePacketData bool
}

var flags = Flags{}
var logger *zap.Logger
var sugar *zap.SugaredLogger
var bot *Bot

func init() {
	flag.StringVar(&flags.version, "version", "", "Version of the application")
	flag.StringVar(&flags.mode, "mode", "intercept", "Mode to run in: intercept, inspect, or tap")
	flag.StringVar(&flags.ip, "ip", "", "IP of network interface to listen/capture on")
	flag.IntVar(&flags.port, "port", 6767, "TCP port to listen/capture on")
	flag.BoolVar(&flags.setTitle, "set-title", false, "Set the console title evrproxy")
	flag.StringVar(&flags.destination, "upstream", "", "Upstream server host:port")
	flag.IntVar(&flags.snaplen, "snaplength", 262144, "Snapshot length (tap mode only)")
	flag.BoolVar(&flags.promisc, "promiscuous", false, "Promiscuous mode (tap mode only)")
	flag.StringVar(&flags.botChannel, "bot-channel", "", "Discord channel to send messages to")
	flag.StringVar(&flags.botToken, "bot-token", "", "Discord bot token")
	flag.StringVar(&flags.msgFormat, "msg-encoding", "json", "Output the parsed messages as JSON or YAML")
	flag.IntVar(&flags.rateLimit, "rate-limit", 10, "Rate limit in messages per second")
	flag.StringVar(&flags.includeFrom, "include-from", "", "File containing a list of message symbols to include")
	flag.StringVar(&flags.excludeFrom, "exclude-from", "", "File containing a list of message symbols to exclude")
	flag.StringVar(&flags.include, "include", "", "Comma separated list of message symbols to include")
	flag.BoolVar(&flags.listSymbols, "list-symbols", false, "List known message symbols")
	flag.StringVar(&flags.logPath, "log", "", "Enable logging to file")
	flag.BoolVar(&flags.debug, "debug", false, "Enable debug logging")
	flag.StringVar(&flags.outputDir, "output", "", "Directory to output mismatched packets to")
	flag.BoolVar(&flags.timestamp, "timestamp", false, "Add a timestamp to the output files")
	flag.BoolVar(&flags.savePacketData, "save-packets", false, "Store packet bytes in output directory")
	flag.BoolVar(&flags.decodePacketData, "decode-packets", false, "Decode packet data")
	flag.Parse()

	if flags.listSymbols {
		for k, v := range evr.SymbolTypes {
			fmt.Printf("0x%016x : % -36s : %T\n", k, evr.Symbol(k).String(), v)
		}
		os.Exit(0)
	}

	level := zap.InfoLevel
	if flags.debug {
		level = zap.DebugLevel
	}
	// Log to a file
	if flags.logPath != "" {
		// Create a new logger that logs to a file
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
		cfg.OutputPaths = []string{flags.logPath}
		cfg.ErrorOutputPaths = []string{flags.logPath}

		cfg.Level.SetLevel(level)
		fileLogger, _ := cfg.Build()

		defer fileLogger.Sync() // flushes buffer, if any

		// Create a new logger that logs to the console
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
		cfg.OutputPaths = []string{"stdout"}
		cfg.ErrorOutputPaths = []string{"stderr"}

		cfg.Level.SetLevel(level)

		consoleLogger, _ := cfg.Build()
		defer consoleLogger.Sync() // flushes buffer, if any

		// Create a new logger that logs to both the file and the console
		core := zapcore.NewTee(
			fileLogger.Core(),
			consoleLogger.Core(),
		)
		logger = zap.New(core)
	} else {
		cfg := zap.NewProductionConfig()
		cfg.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.RFC3339)
		cfg.Level.SetLevel(level)
		logger, _ = cfg.Build()
		defer logger.Sync() // flushes buffer, if any
	}

	defer logger.Sync() // flushes buffer, if any
	sugar = logger.Sugar()
}

func main() {

	if flags.setTitle {
		fmt.Println("\033]0;evrproxy\a")
	}

	if err := godotenv.Load(); err != nil {
		sugar.Warnf("No .env file found")
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	prefix := strings.ToUpper(flags.mode)

	logger.Info("Starting evrproxy", zap.String("mode", prefix), zap.String("port", fmt.Sprintf("%d", flags.port)), zap.String("destination", flags.destination))

	if flags.botToken == "" {
		flags.botToken = os.Getenv("DISCORD_BOT_TOKEN")
	}
	if flags.botChannel == "" {
		flags.botChannel = os.Getenv("DISCORD_BOT_CHANNEL")
	}
	var marshalFn func(in any) (out []byte, err error)
	switch flags.msgFormat {
	case "yaml":
		marshalFn = func(in any) (out []byte, err error) {
			return yaml.Marshal(in)
		}
	default:
		marshalFn = func(in any) (out []byte, err error) {
			return json.MarshalIndent(in, "", "  ")
		}
	}

	includes := make([]evr.Symbol, 0)
	if flags.include != "" {
		includes = append(includes, parseSymbols(strings.Split(flags.include, ","))...)
	}
	if flags.includeFrom != "" {
		// Read the file into the slice
		data, err := os.ReadFile(flags.includeFrom)
		if err != nil {
			logger.Fatal("Error reading include file", zap.Error(err))
		}
		includes = append(includes, parseSymbols(strings.Split(string(data), "\n"))...)
	}

	excludes := make([]evr.Symbol, 0)
	if flags.exclude != "" {
		excludes = append(excludes, parseSymbols(strings.Split(flags.exclude, ","))...)
	}

	if flags.excludeFrom != "" {
		// Read the file into the slice
		data, err := os.ReadFile(flags.excludeFrom)
		if err != nil {
			logger.Fatal("Error reading exclude file", zap.Error(err))
		}
		excludes = append(excludes, parseSymbols(strings.Split(string(data), "\n"))...)
	}

	if len(includes) > 0 && len(excludes) > 0 {
		logger.Fatal("Cannot include and exclude symbols at the same time")
	}

	if len(includes) > 0 {
		logger.Info("Including Symbols", zap.Any("symbols", includes))
	}
	if len(excludes) > 0 {
		logger.Info("Excluding Symbols", zap.Any("symbols", excludes))
	}

	symbols := make([]evr.Symbol, len(evr.SymbolTypes))
	for k := range evr.SymbolTypes {
		if len(includes) > 0 {
			if !lo.Contains(includes, evr.Symbol(k)) {
				continue
			}
		}
		if len(excludes) > 0 {
			if lo.Contains(excludes, evr.Symbol(k)) {
				continue
			}
		}
		symbols = append(symbols, evr.Symbol(k))
	}
	if len(symbols) == 0 {
		logger.Fatal("No symbols to listen for")
	}
	var fn func(h *httpStream, messages []evr.Message)
	if flags.botToken != "" {
		logger.Info("Discord Bot Token", zap.String("token", flags.botToken))
		bot = NewBot(context.Background(), logger, flags.botToken, flags.botChannel, flags.msgFormat, flags.rateLimit, marshalFn)

		fn = bot.inspectMessagesFn
	} else {
		fn = func(h *httpStream, messages []evr.Message) {
			logger.Info("Messages", zap.Any("messages", messages))
		}
	}

	if flags.mode == "tap" {
		go StartTap(logger, fn, flags.ip, int32(flags.snaplen), flags.promisc, flags.port, symbols)
	} else {
		listenAddr := fmt.Sprintf(":%d", flags.port)
		http.HandleFunc("/", handleProxyClient)
		go http.ListenAndServe(listenAddr, nil)
	}

	<-interrupt

}

func parseSymbols(strs []string) []evr.Symbol {
	symbols := make([]evr.Symbol, 0, len(strs))
	for _, s := range strs {
		if s == "" {
			continue
		}
		v := evr.ToSymbol(s)
		if v == evr.Symbol(0) {
			logger.Fatal("Invalid symbol", zap.String("symbol", s))
		}
		symbols = append(symbols, v)
	}
	return symbols
}

func handleProxyClient(w http.ResponseWriter, r *http.Request) {
	// Parse the existing X-Forwarded-For header.
	xff := r.Header.Get("X-Forwarded-For")

	// Add a comma and space to the existing X-Forwarded-For header, if it exists.
	if xff != "" {
		xff = xff + ", "
	}

	// Get the client's IP address.
	s := strings.Split(r.RemoteAddr, ":")
	remoteIP := s[0]

	// Add the client's IP address to the X-Forwarded-For header.
	r.Header.Add("X-Forwarded-For", xff+remoteIP)

	// Get the destination
	dest := *r.URL

	if flags.destination == "" {
		// Get the destination from the URL parameter
		flags.destination = r.URL.Query().Get("dst")
	}

	dest.Host = flags.destination

	if r.Header.Get("Upgrade") != "websocket" {
		dest.Scheme = "http"
		// Handle as a regular HTTP proxy
		proxySessionHTTP(w, r, dest)
		return
	}
	dest.Scheme = "ws"
	proxySessionWS(w, r, dest)

}

func proxySessionWS(w http.ResponseWriter, r *http.Request, dest url.URL) {
	sugar.Infof("Received WebSocket connection from %s", r.RemoteAddr)
	// Handle as a WebSocket proxy
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		sugar.Errorf("Error upgrading to websocket:", err)
		return
	}
	defer clientConn.Close()

	// Update the host header
	r.Header.Set("Host", dest.Host)

	// List of headers to remove
	var headersToRemove = []string{
		"Upgrade",
		"Connection",
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Version",
	}

	// Remove headers
	for _, header := range headersToRemove {
		r.Header.Del(header)
	}

	logger.Debug("Including Headers", zap.Any("headers", r.Header))
	serverConn, wsr, err := websocket.DefaultDialer.Dial(dest.String(), r.Header)
	if err != nil {
		sugar.Errorf("dial:", err)
		if wsr != nil {
			sugar.Errorf("got HTTP response %d: %s", wsr.StatusCode, wsr.Body)
			return
		}

	}

	if serverConn == nil {
		sugar.Errorf("Failed to connect to %s", dest.String())
		return
	}

	defer serverConn.Close()

	go proxyWS(serverConn, clientConn, Inbound)
	proxyWS(clientConn, serverConn, Outbound)
}

// proxySessionWS forwards messages from src to dst.
func proxyWS(src *websocket.Conn, dst *websocket.Conn, name string) {
	defer dst.Close()
	srcAddr := src.NetConn().RemoteAddr()
	dstAddr := dst.NetConn().RemoteAddr()
	var messages []evr.Message
	for {
		if dst == nil || src == nil {
			return
		}
		arrow := fmt.Sprintf("%s -> %s", srcAddr, dstAddr)

		msgType, inBytes, err := src.ReadMessage()
		if err != nil {
			sugar.Errorf("read: %v", err)
			return
		}
		// Decode the message(s).

		if messages, err = evr.ParsePacket(inBytes); err != nil {
			sugar.Errorf("err: %v", err)
		}
		logEntries := make([][]zap.Field, 0)
		for _, message := range messages {
			entry := []zap.Field{
				zap.Any("message", message),
				zap.String("type", fmt.Sprintf("%T", message)),
			}
			if flags.debug {
				entry = append(entry, zap.Any("payload", message))
			}
			logEntries = append(logEntries, entry)
		}

		fields := []zap.Field{
			zap.String("direction", name),
			zap.String("flow", arrow),
			zap.String("srcAddr", srcAddr.String()),
			zap.String("dstAddr", dstAddr.String()),
			zap.Any("messages", logEntries),
		}

		logger.Info("packet", fields...)

		// Re-encode the message(s).
		outBytes := []byte{}
		for _, message := range messages {

			b, err := evr.Marshal(message)
			if err != nil {
				sugar.Errorf("failed to marshal: %v", err)
			}

			outBytes = append(outBytes, b...)
		}

		if flags.logPath != "" || !bytes.Equal(inBytes, outBytes) {
			writePacketSetToFile(inBytes, outBytes)
		}
		// compare outBytes to inBytes and show differences

		if flags.mode != "intercept" {
			outBytes = inBytes
		}

		if err = dst.WriteMessage(msgType, outBytes); err != nil {
			sugar.Errorf("Error writing message: %v", err)
			return
		}
	}
}

func writePacketSetToFile(in []byte, out []byte) {
	var err error
	var inpacket []evr.Message
	if inpacket, err = evr.ParsePacket(in); err != nil {
		sugar.Errorf("err: %v", err)
	}

	var outpacket []evr.Message
	if outpacket, err = evr.ParsePacket(out); err != nil {
		sugar.Errorf("err: %v", err)
	}

	if len(outpacket) != len(inpacket) {
		sugar.Errorf("rewritten packet does not have the same number of envelopes as the original")
		return
	}

	ins := make([][]byte, 0)
	for _, in := range evr.SplitPacket(in) {
		if len(in) == 0 {
			continue
		}
		ins = append(ins, in)
	}

	outs := make([][]byte, 0)
	for _, out := range evr.SplitPacket(out) {
		if len(out) == 0 {
			continue
		}
		outs = append(outs, out)
	}

	if !bytes.Equal(in, out) {
		sugar.Debugf("Original Packet Messages:  %s", lo.Map(inpacket, func(m evr.Message, n int) string { return fmt.Sprintf("%s", m) }))
		sugar.Debugf("Original Packet Messages:  %s", lo.Map(outpacket, func(m evr.Message, n int) string { return fmt.Sprintf("%s", m) }))
		//sugar.Infof("Original bytes: %s", ins)
		//sugar.Infof("Rewritten bytes: %s", outs)

		if len(outs) != len(ins) {
			sugar.Debugf("rewritten packet does not have the same number of envelopes as the original (%d vs %d)", len(outs), len(ins))
			sugar.Debugf("Packet difference: %s", cmp.Diff(in, out))
			return
		}
		for i := range ins {
			if !bytes.Equal(ins[i], outs[i]) {
				sugar.Debugf("Diff Message #%d: %s", i, cmp.Diff(ins[i], outs[i]))
			}
		}
	}
	if flags.outputDir == "" {
		return
	}

	type mismatchedMessage struct {
		InBytes    []byte
		OutBytes   []byte
		InMessage  []evr.Message
		OutMessage []evr.Message
	}

	// split the packet into individual messages, and save each set of files. the json file will contain the original and rewritten packets, and the binary files will contain the original and rewritten bytes
	for i := range ins {
		in := append(evr.MessageMarker, ins[i]...)
		out := append(evr.MessageMarker, outs[i]...)

		// try to unmarshal them
		var inmessage []evr.Message
		if inmessage, err = evr.ParsePacket(in); err != nil {
			sugar.Errorf("err: %v", err)
		}

		var outmessage []evr.Message
		if outmessage, err = evr.ParsePacket(out); err != nil {
			sugar.Errorf("err: %v", err)
		}

		data := mismatchedMessage{
			InBytes:    in,
			OutBytes:   out,
			InMessage:  inmessage,
			OutMessage: outmessage,
		}

		packetJson, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			sugar.Errorf("failed to marshal packet: %v", err)
		}
		typname := ""
		if len(inmessage) > 0 {
			typname = evr.SymbolOf(inmessage[0]).String()
		} else {
			typname = fmt.Sprintf("0x%x", binary.LittleEndian.Uint64(in[8:16]))
		}
		// Save the struct to a json file in the output directory
		ts := ""
		if flags.timestamp {
			ts = time.Now().Format("2006-01-02T15:04:05") + "_"
		}
		if err := os.WriteFile(fmt.Sprintf("%s/%s%s.json", flags.outputDir, ts, typname), packetJson, 0644); err != nil {
			sugar.Errorf("failed to write file: %v", err)
		}

		// Write the original bytes to a binary file
		if err := os.WriteFile(fmt.Sprintf("%s/%s%s_in.bin", flags.outputDir, ts, typname), in, 0644); err != nil {
			sugar.Errorf("failed to write file: %v", err)
		}

		// Write the rewritten bytes to a binary file
		if err := os.WriteFile(fmt.Sprintf("%s/%s%s_out.bin", flags.outputDir, ts, typname), out, 0644); err != nil {
			sugar.Errorf("failed to write file: %v", err)
		}
	}
}

func writeMessageDataToFile(data []byte, symbol evr.Symbol, withTimestamp bool) error {
	// Save the struct to a binary file in the output directory
	ts := ""
	if withTimestamp {
		ts = time.Now().Format("2006-01-02T15:04:05") + "_"
	}
	fn := fmt.Sprintf("%s/%s%s.bin", flags.outputDir, ts, symbol.String())
	if err := os.WriteFile(fn, data, 0644); err != nil {
		sugar.Errorf("failed to write file: %v", err)
		return err
	}
	return nil
}

func proxySessionHTTP(w http.ResponseWriter, r *http.Request, dest url.URL) {
	sugar.Infof("Received HTTP connection from %s", r.RemoteAddr)
	// Create a new HTTP request for the target server.
	req, err := http.NewRequest(r.Method, dest.String(), r.Body)
	if err != nil {
		sugar.Errorf("Error creating request:", err)
		return
	}
	req.Header = r.Header
	req.Header.Del("Proxy-Connection")
	req.Header.Del("Connection")
	req.Header.Del("Keep-Alive")
	req.Header.Del("Proxy-Authenticate")
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Te")
	req.Header.Del("Trailers")
	req.Header.Del("Transfer-Encoding")
	req.Header.Del("Upgrade")

	// Parse the existing X-Forwarded-For header.
	xff := req.Header.Get("X-Forwarded-For")

	// Add a comma and space to the existing X-Forwarded-For header, if it exists.
	if xff != "" {
		xff = xff + ", "
	}

	// Get the client's IP address.
	s := strings.Split(r.RemoteAddr, ":")
	remoteIP := s[0]

	// Add the client's IP address to the X-Forwarded-For header.
	req.Header.Add("X-Forwarded-For", xff+remoteIP)

	// Send the request to the target server.
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		sugar.Errorf("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	// Copy the response headers to the client.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Copy the response body to the client.
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		sugar.Errorf("Error copying response body:", err)
		return
	}
}

type streamFactory struct {
	symbols   []evr.Symbol
	inspectFn func(h *httpStream, messages []evr.Message)
}

type httpStream struct {
	net, transport gopacket.Flow
	r              tcpreader.ReaderStream
	symbols        []evr.Symbol
	inspectFn      func(h *httpStream, messages []evr.Message)
}

func (h *httpStream) run() {
	baseLogger := logger
	// Here, you can process the reassembled TCP stream
	buf := make([]byte, 4096)
	for {
		read, err := h.r.Read(buf)
		if err != nil {
			break // End of stream
		}
		if read > 0 {
			// Process the chunk read
			data := buf[:read]
			// Check for payload
			if len(data) > 0 {
				// Unmask the payload if it's a WebSocket frame
				maskingKey, err := ExtractMaskingKey(data)
				if err == nil { // No error means it's a masked WebSocket frame
					unmaskedPayload := UnmaskWebSocketPayload(maskingKey, data)
					for {
						index := bytes.Index(unmaskedPayload, evr.MessageMarker)
						if index == -1 {
							// The connection isn't of any interest, so break out of the loop
							break
						}
						if len(unmaskedPayload) < index+24 {
							// The payload is too short to contain a message, so break out of the loop
							break
						}
						logger := baseLogger.With(zap.String("src", h.net.Src().String()))
						logger = logger.With(zap.String("dst", h.net.Dst().String()))
						symbol := binary.LittleEndian.Uint64(unmaskedPayload[index+8 : index+16])
						logger.Info("Symbol", zap.String("symbol", evr.ToSymbol(symbol).String()))
						if lo.Contains(h.symbols, evr.Symbol(symbol)) {
							// Do something with the payload
							size := int(binary.LittleEndian.Uint64(unmaskedPayload[index+16 : index+24]))
							if len(unmaskedPayload) < index+24+size {
								// The payload is too short to contain a message, so break out of the loop
								logger.Warn("Payload too short to contain a message")
								// If saving packets, write the packet to disk
								if flags.savePacketData {
									if err := writeMessageDataToFile(unmaskedPayload[index:], evr.Symbol(symbol), flags.timestamp); err != nil {
										logger.Warn("Error writing message data to file", zap.Error(err))
									}
								}

								break
							}
							if flags.savePacketData {
								if err := writeMessageDataToFile(unmaskedPayload[index:index+24+size], evr.Symbol(symbol), flags.timestamp); err != nil {
									logger.Warn("Error writing message data to file", zap.Error(err))
								}
							}
							// Create a slice of the payload that contains the message
							messagePayload := unmaskedPayload[index : index+24+size]
							// Unmarshal the payload as evr messages
							if len(messagePayload) > 0 {
								messages, err := processPayload(messagePayload)
								if err != nil {
									logger.Error("Error unmarshalling message", zap.Error(err))
								}
								h.inspectFn(h, messages)
							}
						}

						unmaskedPayload = unmaskedPayload[index+1:]
					}
				}
			}
		}
	}
}

func processPayload(payload []byte) ([]evr.Message, error) {
	// get the size from the payload
	size := int(binary.LittleEndian.Uint64(payload[16:24]))
	// Create a slice of the payload that contains the message
	messagePayload := payload[:24+size]
	// Unmarshal the payload as evr messages
	return evr.ParsePacket(messagePayload)
}

func (s *streamFactory) New(net, transport gopacket.Flow) tcpassembly.Stream {
	h := &httpStream{
		net:       net,
		transport: transport,
		r:         tcpreader.NewReaderStream(),
		symbols:   s.symbols,
		inspectFn: s.inspectFn,
	}
	go h.run() // Start processing the stream in a goroutine

	return &h.r // Return a reference to the ReaderStream
}

func StartTap(logger *zap.Logger, inspectFn func(*httpStream, []evr.Message), deviceIP string, snapshotLen int32, promiscuous bool, port int, symbols []evr.Symbol) {
	ipToInterface := IPinterfaces()

	// if the ip flag isn't set, then print the interface IP Addresses
	if deviceIP == "" {
		for ip, iface := range ipToInterface {
			logger.Info("Interface", zap.String("IP", ip), zap.String("Interface", iface))
		}
		return
	}

	// get the interface name from the ip address
	selectedDeviceName, ok := ipToInterface[deviceIP]
	if !ok {
		logger.Fatal("Interface not found")
	}

	handle, err := pcap.OpenLive(selectedDeviceName, snapshotLen, promiscuous, pcap.BlockForever)
	if err != nil {
		logger.Fatal("Error opening device", zap.Error(err))
	}
	defer handle.Close()

	captureFilter := fmt.Sprintf("tcp and port %d", port)
	logger.Info("Setting BPF filter", zap.String("filter", captureFilter))
	err = handle.SetBPFFilter(captureFilter)
	if err != nil {
		logger.Fatal("Error setting BPF filter", zap.Error(err))
	}

	streamFactory := &streamFactory{
		symbols:   symbols,
		inspectFn: inspectFn,
	} // Create a new instance of the stream factory
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			assembler.Assemble(packet.NetworkLayer().NetworkFlow(), tcp)
		}
	}
}

func IPinterfaces() map[string]string {
	ipToInterface := make(map[string]string)
	devices, err := pcap.FindAllDevs()
	if err != nil {
		logger.Fatal("Error finding devices", zap.Error(err))
	}

	for _, d := range devices {
		for _, address := range d.Addresses {
			ipToInterface[address.IP.String()] = d.Name
		}
	}
	return ipToInterface
}

// ExtractMaskingKey extracts the masking key from a WebSocket frame.
// It returns the masking key and an error if the frame is not masked or improperly formatted.
func ExtractMaskingKey(frame []byte) ([]byte, error) {
	if len(frame) < 2 { // Check if frame is at least 2 bytes
		return nil, fmt.Errorf("frame too short")
	}

	payloadLen := frame[1] & 0x7F // Mask off the MSB to get the payload length
	maskOffset := 2               // Initial mask offset after the first two bytes

	if payloadLen == 126 {
		maskOffset += 2 // Additional 2 bytes for 16-bit extended payload length
	} else if payloadLen == 127 {
		maskOffset += 8 // Additional 8 bytes for 64-bit extended payload length
	}

	if (frame[1] & 0x80) == 0 {
		return nil, fmt.Errorf("frame not masked")
	}

	if len(frame) < maskOffset+4 { // Check if there's enough bytes for the masking key
		return nil, fmt.Errorf("frame too short for masking key")
	}

	// Extract the 4-byte masking key
	maskingKey := frame[maskOffset : maskOffset+4]

	return maskingKey, nil
}

func UnmaskWebSocketPayload(maskingKey []byte, data []byte) []byte {
	unmaskedData := make([]byte, len(data))
	for i, b := range data {
		unmaskedData[i] = b ^ maskingKey[i%4] // Repeat masking key as needed
	}
	return unmaskedData
}

type Bot struct {
	ctx    context.Context
	logger *zap.Logger
	dg     *discordgo.Session

	botChannel  string
	botToken    string
	rateLimit   int
	msgEncoding string
	marshalFn   func(in any) (out []byte, err error)
}

func NewBot(ctx context.Context, logger *zap.Logger, botToken, botChannel, msgEncoding string, rateLimit int, marshalFn func(in any) (out []byte, err error)) *Bot {
	ctx, cancel := context.WithCancel(ctx)
	// Setup the channel and event loop
	messageCh := make(chan string, 128)
	messageTicker := time.NewTicker(time.Second / time.Duration(rateLimit))
	go func() {
		defer cancel()
		for {
			// Rate limit to rateLimit per second
			select {
			case <-ctx.Done():
				return
			case <-messageTicker.C:
				select {
				case msg := <-messageCh:
					_, err := bot.dg.ChannelMessageSend(bot.botChannel, msg)
					if err != nil {
						logger.Warn("Error sending message to Discord", zap.Error(err))
					}
				default:
				}
			}
		}
	}()

	// Create a new Discord session using the provided bot token.
	dg, err := discordgo.New("Bot " + botToken)
	if err != nil {
		logger.Fatal("Error creating Discord session", zap.Error(err))
	}
	dg.AddHandler(func(s *discordgo.Session, m *discordgo.Ready) {
		logger.Info("Bot is operational", zap.String("username", m.User.String()))
	})
	// Open a websocket connection to Discord and begin listening.
	err = dg.Open()
	if err != nil {
		logger.Fatal("Error opening connection to Discord", zap.Error(err))
	}

	return &Bot{
		ctx:    ctx,
		dg:     dg,
		logger: logger,

		botChannel:  botChannel,
		botToken:    botToken,
		rateLimit:   rateLimit,
		msgEncoding: msgEncoding,
		marshalFn:   marshalFn,
	}
}

type DiscordPacketOutput struct {
	Timestamp time.Time
	Flow      string
	Name      string
	Token     string
	Symbol    string
	Message   evr.Message
}

func (b *Bot) inspectMessagesFn(h *httpStream, messages []evr.Message) {
	logger := b.logger
	// Process the messages
	for _, m := range messages {
		logger.Debug("message", zap.Any("message", m))

		sym := evr.SymbolOf(m)

		name := ""
		if t, ok := evr.SymbolTypes[uint64(sym)]; ok {
			name = fmt.Sprintf("%T ", t)
		}
		token := sym.Token().String()

		o := DiscordPacketOutput{
			Timestamp: time.Now().UTC(),
			Name:      fmt.Sprintf("%s%s (0x%x)", name, token, uint64(sym)),
			Token:     token,
			Symbol:    sym.String(),
			Flow:      fmt.Sprintf("%s to %s", h.net.Src().String(), h.net.Dst().String()),
			Message:   m,
		}
		data, err := b.marshalFn(o)
		if err != nil {
			logger.Error("Error marshalling message", zap.Error(err))
			continue
		}
		_, err = bot.dg.ChannelMessageSend(bot.botChannel, fmt.Sprintf("```%s\n%s\n```", b.msgEncoding, string(data)))
		if err != nil {
			logger.Warn("Error sending message to Discord", zap.Error(err))
		}
	}
}
