package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"time"

	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/gorilla/websocket"
	"github.com/heroiclabs/nakama/v3/server/evr"
	"github.com/joho/godotenv"
	"github.com/samber/lo"
)

// upgrader is used to upgrade the HTTP server connection to the WebSocket protocol.
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Flags struct {
	intercept   bool
	port        int
	outputDir   string
	timestamp   bool
	saveAll     bool
	setTitle    bool
	tapMode     bool
	destination string // host:port
}

var flags = Flags{}

func init() {

	flag.BoolVar(&flags.intercept, "intercept", false, "Enable interception")
	flag.BoolVar(&flags.saveAll, "save", false, "Save a copy of every message to disk")
	flag.IntVar(&flags.port, "port", 6767, "TCP port to listen on")
	flag.StringVar(&flags.outputDir, "output", "", "Directory to output mismatched packets to")
	flag.BoolVar(&flags.timestamp, "add-timestamp", false, "Add a timestamp to the output files")
	flag.BoolVar(&flags.setTitle, "set-title", false, "Set the console title evrproxy")
	flag.BoolVar(&flags.tapMode, "tap", false, "Enable tap mode")
	flag.StringVar(&flags.destination, "upstream", "", "Upstream server host:port")
	flag.Parse()
}

func main() {

	if flags.setTitle {
		fmt.Println("\033]0;evrproxy\a")
	}

	// Rest of the code...
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	http.HandleFunc("/", handleProxyClient)
	prefix := "INSPECT"
	if flags.intercept {
		prefix = "INTERCEPT"
	}

	log.Printf(prefix+"-MODE EVR Debugging Proxy listening on port %d", flags.port)
	go http.ListenAndServe(fmt.Sprintf(":%d", flags.port), nil)

	//go dialLogin(URL_LOGIN, sId, uId)
	//go dialMatch(URL_MATCH, sId, uId)

	<-interrupt

}

func handleProxyClient(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received connection from %s", r.RemoteAddr)

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

	if flags.destination == "" {
		// Get the destination from the URL parameter
		flags.destination = r.URL.Query().Get("dst")
	}

	destURL := *r.URL

	destURL.Host = flags.destination

	if r.Header.Get("Upgrade") != "websocket" {
		// Handle as a regular HTTP proxy
		proxySessionHTTP(w, r, destURL)
		return
	}

	proxySessionWS(w, r, destURL)

}

func proxySessionWS(w http.ResponseWriter, r *http.Request, dsturl url.URL) {
	// Handle as a WebSocket proxy
	clientConn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading to websocket:", err)
		return
	}
	defer clientConn.Close()

	serverConn, wsr, err := websocket.DefaultDialer.Dial(flags.destination, r.Header)
	if err != nil {
		log.Println("dial:", err)
		if wsr != nil {
			log.Fatal(fmt.Printf("response %d: %s", wsr.StatusCode, wsr.Body))
		}
		clientConn.Close()
	}
	if serverConn == nil {
		log.Printf("Failed to connect to %s", dsturl.String())
		return
	}
	defer serverConn.Close()

	go proxyWS(serverConn, clientConn, "server")
	proxyWS(clientConn, serverConn, "client")
}

// proxySessionWS forwards messages from src to dst.
func proxyWS(src *websocket.Conn, dst *websocket.Conn, name string) {
	defer dst.Close()
	ra := src.NetConn().RemoteAddr()
	arrow := ">>>>"
	if name == "server" {
		ra = dst.NetConn().RemoteAddr()
		arrow = "<<<<"
	}
	for {
		if dst == nil || src == nil {
			return
		}
		msgType, inBytes, err := src.ReadMessage()
		if err != nil {
			log.Printf("read: %v", err)
			return
		}
		// Decode the message(s).
		packet := []evr.Message{}
		if err = evr.Unmarshal(inBytes, &packet); err != nil {
			log.Printf("err: %v", err)
		}

		// Re-encode the message(s).
		outBytes := []byte{}
		for _, message := range packet {
			log.Printf("[%s] %s %T(%s): %s", ra, arrow, message, fmt.Sprintf("0x%x", uint64(evr.SymbolOf(message))), message)
			b, err := evr.Marshal(message)
			if err != nil {
				log.Printf("failed to marshal: %v", err)
			}

			outBytes = append(outBytes, b...)
		}

		if flags.saveAll || !bytes.Equal(inBytes, outBytes) {
			writePacketToFile(inBytes, outBytes)
		}
		// compare outBytes to inBytes and show differences

		if !flags.intercept {
			outBytes = inBytes
		}

		if err = dst.WriteMessage(msgType, outBytes); err != nil {
			log.Printf("Error writing message: %v", err)
			return
		}
	}
}
func writePacketToFile(in []byte, out []byte) {
	inpacket := []evr.Message{}
	if err := evr.Unmarshal(in, &inpacket); err != nil {
		log.Printf("err: %v", err)
	}

	outpacket := []evr.Message{}
	if err := evr.Unmarshal(out, &outpacket); err != nil {
		log.Printf("err: %v", err)
	}

	if len(outpacket) != len(inpacket) {
		log.Printf("rewritten packet does not have the same number of envelopes as the original")
		return
	}

	if bytes.Equal(in, out) {
		log.Printf("Packets are identical")
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
		log.Printf("Original Packet Messages:  %s", lo.Map(inpacket, func(m evr.Message, n int) string { return fmt.Sprintf("%s", m) }))
		log.Printf("Original Packet Messages:  %s", lo.Map(outpacket, func(m evr.Message, n int) string { return fmt.Sprintf("%s", m) }))
		//log.Printf("Original bytes: %s", ins)
		//log.Printf("Rewritten bytes: %s", outs)

		if len(outs) != len(ins) {
			log.Printf("rewritten packet does not have the same number of envelopes as the original (%d vs %d)", len(outs), len(ins))
			log.Printf("Packet difference: %s", cmp.Diff(in, out))
			return
		}
		for i := range ins {
			if !bytes.Equal(ins[i], outs[i]) {
				log.Printf("Diff Message #%d: %s", i, cmp.Diff(ins[i], outs[i]))
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
		inmessage := []evr.Message{}
		if err := evr.Unmarshal(in, &inpacket); err != nil {
			log.Printf("err: %v", err)
		}

		outmessage := []evr.Message{}
		if err := evr.Unmarshal(out, &outpacket); err != nil {
			log.Printf("err: %v", err)
		}

		data := mismatchedMessage{
			InBytes:    in,
			OutBytes:   out,
			InMessage:  inmessage,
			OutMessage: outmessage,
		}

		packetJson, err := json.MarshalIndent(data, "", "    ")
		if err != nil {
			log.Printf("failed to marshal packet: %v", err)
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
			log.Printf("failed to write file: %v", err)
		}

		// Write the original bytes to a binary file
		if err := os.WriteFile(fmt.Sprintf("%s/%s%s_in.bin", flags.outputDir, ts, typname), in, 0644); err != nil {
			log.Printf("failed to write file: %v", err)
		}

		// Write the rewritten bytes to a binary file
		if err := os.WriteFile(fmt.Sprintf("%s/%s%s_out.bin", flags.outputDir, ts, typname), out, 0644); err != nil {
			log.Printf("failed to write file: %v", err)
		}
	}
}

func proxySessionHTTP(w http.ResponseWriter, r *http.Request, dest url.URL) {
	// Create a new HTTP request for the target server.
	req, err := http.NewRequest(r.Method, dest.String(), r.Body)
	if err != nil {
		log.Println("Error creating request:", err)
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
		log.Println("Error sending request:", err)
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
		log.Println("Error copying response body:", err)
		return
	}
}
