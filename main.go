package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"

	"github.com/GaoMjun/goutils"
)

func init() {
	log.SetFlags(log.Ltime | log.Lmicroseconds | log.Lshortfile)
}

var ca *x509.Certificate
var pk *rsa.PrivateKey
var keyLogWriter io.Writer

func main() {
	addr := flag.String("l", "127.0.0.1:8080", "http proxy server address, default 127.0.0.1:8080")
	capath := flag.String("ca", "htun.cer", "certificate file path")
	pkpath := flag.String("pk", "htun.key", "private key file path")
	sslkeylogfile := flag.String("sslkeylog", "sslkey.log", "sslkeylog file path")
	flag.Parse()

	var (
		err error
		l   net.Listener
	)
	defer func() {
		if err != nil {
			log.Println(err)
		}
	}()

	if ca, pk, err = goutils.LoadCert(*capath, *pkpath); err != nil {
		return
	}

	if keyLogWriter, err = os.OpenFile(*sslkeylogfile, os.O_WRONLY, os.ModePerm); err != nil {
		return
	}

	if l, err = net.Listen("tcp", *addr); err != nil {
		return
	}
	log.Println("http proxy server run at " + *addr)

	for {
		var conn net.Conn
		if conn, err = l.Accept(); err != nil {
			log.Println(err)

			continue
		}

		go handleConn(conn, false)
	}
}

func handleConn(conn net.Conn, https bool) {
	var (
		err error
		req *http.Request
	)
	defer func() {
		if err != nil {
			conn.Close()
			log.Println(err)
		}
	}()

	if req, err = http.ReadRequest(bufio.NewReader(conn)); err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		if _, err = fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}

		if req.URL.Port() == "80" {
			handleConn(conn, false)
			return
		}

		conn = tls.Server(conn, &tls.Config{
			GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return goutils.Cert(info.ServerName, ca, pk)
			},
		})

		handleConn(conn, true)

		return
	}

	pipeConn(conn, req, https)
}

func pipeConn(local net.Conn, req *http.Request, https bool) {
	var (
		err error

		reqBytes []byte

		hostport string

		remote net.Conn
	)
	defer func() {
		if err != nil {
			local.Close()
			log.Println(err)
		}
	}()

	hostport = req.Host
	if req.URL.Port() == "" {
		if https {
			hostport += ":443"
		} else {
			hostport += ":80"
		}
	}

	if https {
		if reqBytes, err = httputil.DumpRequest(req, true); err != nil {
			return
		}
	} else {
		if reqBytes, err = httputil.DumpRequestOut(req, true); err != nil {
			return
		}
	}

	if remote, err = net.Dial("tcp", hostport); err != nil {
		return
	}

	if https {
		remote = tls.Client(remote, &tls.Config{
			KeyLogWriter:       keyLogWriter,
			InsecureSkipVerify: true,
		})
	}

	remote.Write(reqBytes)
	goutils.Pipe(local, remote)
}
