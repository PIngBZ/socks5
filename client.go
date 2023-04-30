package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"
)

// Client defines parameters for running socks client.
type Client struct {
	// ProxyAddr in the form "host:port". It not be empty.
	ProxyAddr string

	// Timeout specifies a time limit for requests made by this
	// Client. The timeout includes connection time, reading the response body.
	//
	// A Timeout of zero means no timeout.
	//
	// The Client cancels requests to the underlying Transport
	// as if the Request's Context ended.
	HandshakeTimeout time.Duration

	DialTimeout time.Duration

	// method mapping to the authenticator
	Auth map[METHOD]Authenticator

	// ErrorLog specifics an options logger for errors accepting
	// If nil, logging is done via log package's standard logger.
	ErrorLog *log.Logger

	Dialer func(client *Client, request *Request) (net.Conn, error)
}

// UserPasswd provide socks5 Client Username/Password Authenticator.
type UserPasswd struct {
	Username string
	Password string
}

// Authenticate socks5 Client Username/Password Authentication.
func (c *UserPasswd) Authenticate(in io.Reader, out io.Writer) error {
	//This begins with the client producing a Username/Password request:
	//    +----+------+----------+------+----------+
	//    |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
	//    +----+------+----------+------+----------+
	//    | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
	//    +----+------+----------+------+----------+
	_, err := out.Write(append(append(append([]byte{0x01, byte(len(c.Username))}, []byte(c.Username)...), byte(len(c.Password))), []byte(c.Password)...))
	if err != nil {
		return err
	}
	//Get reply, the following response:

	//    +----+--------+
	//    |VER | STATUS |
	//    +----+--------+
	//    | 1  |   1    |
	//    +----+--------+
	tmp, err := ReadNBytes(in, 2)
	if err != nil {
		return err
	}
	if tmp[0] != 0x01 {
		return errors.New("not support method")
	}
	if tmp[1] != SUCCESSED {
		return errors.New("user authentication failed")
	}
	return nil
}

// handshake socks TCP connect,get a tcp connect and reply addr
func (clt *Client) handshake(request *Request) (conn net.Conn, replyAddr *Address, err error) {

	// dial to Socks server.
	var proxyStreamConn net.Conn

	if clt.Dialer != nil {
		proxyStreamConn, err = clt.Dialer(clt, request)
	} else if clt.DialTimeout != 0 {
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", clt.ProxyAddr, clt.DialTimeout)
		if err == nil {
			proxyStreamConn = conn
		}
	} else {
		// get Socks server Address
		var proxyTCPAddr *net.TCPAddr
		proxyTCPAddr, err = net.ResolveTCPAddr("tcp", clt.ProxyAddr)
		if err == nil {
			proxyStreamConn, err = net.DialTCP("tcp", nil, proxyTCPAddr)
		}
	}

	if err != nil {
		return nil, nil, err
	}

	if clt.HandshakeTimeout != 0 {
		err = proxyStreamConn.SetDeadline(time.Now().Add(clt.HandshakeTimeout))
		if err != nil {
			proxyStreamConn.Close()
			return nil, nil, err
		}
		defer proxyStreamConn.SetDeadline(time.Time{})
	}

	// process handshake by version
	if request.VER == Version5 {
		replyAddr, err = clt.handShake5(request, proxyStreamConn)
	} else {
		proxyStreamConn.Close()
		return nil, nil, errors.New("socks4(a) client had been disabled")
	}

	// handshake wrong.
	if err != nil {
		proxyStreamConn.Close()
		return nil, nil, err
	}

	return proxyStreamConn, replyAddr, nil
}

// handShake5 Socks 5 version of the connection handshake
func (clt *Client) handShake5(request *Request, proxyStreamConn net.Conn) (*Address, error) {
	err := clt.authentication(proxyStreamConn)
	if err != nil {
		return nil, err
	}
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return nil, err
	}
	// The SOCKS request is formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if _, err := proxyStreamConn.Write(append([]byte{request.VER, request.CMD, request.RSV}, destAddrByte...)); err != nil {
		return nil, err
	}
	// reply formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	reply := &Reply{}
	tmp, err := ReadNBytes(proxyStreamConn, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
	}
	reply.VER, reply.REP, reply.RSV = tmp[0], tmp[1], tmp[2]
	if reply.VER != Version5 {
		return nil, fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
	}
	// read address
	serverBoundAddr, _, err := readAddress(proxyStreamConn, request.VER)
	if err != nil {
		return nil, fmt.Errorf("failed to get reply address, %v", err)
	}
	reply.Address = serverBoundAddr
	if reply.REP != SUCCESSED {
		return nil, fmt.Errorf("server refuse client request, %s", rep2Str[reply.REP])
	}
	return reply.Address, nil
}

// authentication
func (clt *Client) authentication(proxyConn net.Conn) error {
	var methods []byte
	for method := range clt.Auth {
		methods = append(methods, method)
	}
	// The client connects to the server, and sends a version identifier/method selection message:
	//    +----+----------+----------+
	//    |VER | NMETHODS | METHODS  |
	//    +----+----------+----------+
	//    | 1  |    1     | 1 to 255 |
	//    +----+----------+----------+
	_, err := proxyConn.Write(append([]byte{Version5, byte(len(methods))}, methods...))
	if err != nil {
		return nil
	}
	//Get reply, a METHOD selection message:
	//    +----+--------+
	//    |VER | METHOD |
	//    +----+--------+
	//    | 1  |   1    |
	//    +----+--------+
	reply, err := ReadNBytes(proxyConn, 2)
	if err != nil {
		return err
	}
	if reply[0] != Version5 {
		return &VersionError{reply[0]}
	}

	// Is client has this method?
	if _, ok := clt.Auth[reply[1]]; !ok {
		return &MethodError{reply[1]}
	}

	// process authentication sub negotiation
	err = clt.Auth[reply[1]].Authenticate(proxyConn, proxyConn)
	if err != nil {
		return err
	}

	return nil
}

// Connect send CONNECT Request. Returned a connected proxy connection.
func (clt *Client) Connect(ver VER, dest string) (net.Conn, error) {
	if ver != Version5 {
		return nil, &VersionError{ver}
	}

	destAddr, err := ParseAddress(dest)
	if err != nil {
		return nil, err
	}
	req := &Request{
		VER:     ver,
		CMD:     CONNECT,
		RSV:     0,
		Address: destAddr,
	}

	conn, _, err := clt.handshake(req)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// UDPForward send UDP_ASSOCIATE Request.
// The laddr Param specific Client address to send udp datagram.
// If laddr is empty string, a local address (127.0.0.1:port) is automatically chosen.
// If port is occupied will return error.
func (clt *Client) UDPForward(laddr string) (*UDPConn, error) {
	if laddr == "" {
		laddr = "127.0.0.1:0"
	}

	// split laddr to host/port
	host, portStr, err := net.SplitHostPort(laddr)
	if err != nil {
		return nil, err
	}
	p, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	port := uint16(p)

	// zero port, will automatically chosen.
	if port == 0 {
		err, port = GetRandomPort("udp")
		if err != nil {
			return nil, errors.New("automatically chosen port fail")
		}
		laddr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	// get addr
	addr, err := ParseAddress(laddr)
	if err != nil {
		return nil, err
	}

	req := &Request{
		VER:     Version5,
		CMD:     UDP_ASSOCIATE,
		RSV:     0,
		Address: addr,
	}

	// Handshake base on TCP connection
	proxyStreamConn, UDPRelayAddr, err := clt.handshake(req)
	if err != nil {
		return nil, err
	}

	// Get local UDP addr
	localUDPAddr, err := addr.UDPAddr()
	if err != nil {
		return nil, err
	}

	// Get udp relay server bind addr.
	serverListenUDPAddr, err := UDPRelayAddr.UDPAddr()
	if err != nil {
		return nil, err
	}

	// Dial UDP relay Server
	err = IsFreePort("udp", port)
	if err != nil {
		proxyStreamConn.Close()
		return nil, fmt.Errorf("port %d is occupied", port)
	}
	proxyUDPConn, err := net.DialUDP("udp", localUDPAddr, serverListenUDPAddr)
	if err != nil {
		proxyStreamConn.Close()
		return nil, err
	}
	return NewUDPConn(proxyUDPConn, proxyStreamConn), nil
}

// Bind send BIND Request. return 4 params:
// 1. Server bind address.
// 2. a readable chan to recv second reply from socks server.
// 3. A connection that is not immediately available, until read a nil from err chan.
// 4. An error, indicate the first reply result. If nil, successes.
func (clt *Client) Bind(ver VER, destAddr string) (*Address, <-chan error, net.Conn, error) {
	dest, err := ParseAddress(destAddr)
	if err != nil {
		return nil, nil, nil, err
	}

	request := &Request{
		Address: dest,
		CMD:     BIND,
		VER:     ver,
	}

	var proxyConn net.Conn
	if clt.Dialer != nil {
		proxyConn, err = clt.Dialer(clt, request)
	} else if clt.DialTimeout != 0 {
		proxyConn, err = net.DialTimeout("tcp", clt.ProxyAddr, clt.DialTimeout)
	} else {
		proxyConn, err = net.Dial("tcp", clt.ProxyAddr)
	}
	if err != nil {
		clt.logf()(err.Error())
		return nil, nil, nil, err
	}
	if clt.HandshakeTimeout != 0 {
		err = proxyConn.SetDeadline(time.Now().Add(clt.HandshakeTimeout))
		if err != nil {
			clt.logf()(err.Error())
			return nil, nil, nil, err
		}
		defer proxyConn.SetDeadline(time.Time{})
	}
	switch request.VER {
	case Version5:
		serverBindAddr, secondReply, err := clt.bind5(request, proxyConn)
		if err != nil {
			proxyConn.Close()
			clt.logf()(err.Error())
			return nil, nil, nil, err
		}
		return serverBindAddr, secondReply, proxyConn, nil
	default:
		proxyConn.Close()
		return nil, nil, nil, &VersionError{request.VER}
	}
}

// bind5 socks5 bind
func (clt *Client) bind5(request *Request, proxyBindConn net.Conn) (*Address, <-chan error, error) {
	err := clt.authentication(proxyBindConn)
	if err != nil {
		return nil, nil, err
	}
	destAddrByte, err := request.Address.Bytes(Version5)
	if err != nil {
		return nil, nil, err
	}
	// The SOCKS request is formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//	//    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	//	//    +----+-----+-------+------+----------+----------+
	//	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	if _, err := proxyBindConn.Write(append([]byte{request.VER, request.CMD, request.RSV}, destAddrByte...)); err != nil {
		return nil, nil, err
	}
	// reply formed as follows:
	//    +----+-----+-------+------+----------+----------+
	//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	//    +----+-----+-------+------+----------+----------+
	//    | 1  |  1  | X'00' |  1   | Variable |    2     |
	//    +----+-----+-------+------+----------+----------+
	reply := &Reply{}
	tmp, err := ReadNBytes(proxyBindConn, 3)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get reply version and command and reserved, %v", err)
	}
	reply.VER, reply.REP, reply.RSV = tmp[0], tmp[1], tmp[2]
	if reply.VER != Version5 {
		return nil, nil, fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
	}
	// read address
	serverBoundAddr, _, err := readAddress(proxyBindConn, request.VER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get reply address, %v", err)
	}
	reply.Address = serverBoundAddr
	if reply.REP != SUCCESSED {
		return nil, nil, fmt.Errorf("server refuse client request, %s,when first time reply", rep2Str[reply.REP])
	}
	errorChan := make(chan error)
	go func() {
		reply2 := &Reply{}
		// The second time reply formed as follows:
		//    +----+-----+-------+------+----------+----------+
		//    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
		//    +----+-----+-------+------+----------+----------+
		//    | 1  |  1  | X'00' |  1   | Variable |    2     |
		//    +----+-----+-------+------+----------+----------+
		tmp, err := ReadNBytes(proxyBindConn, 3)
		if err != nil {
			errorChan <- fmt.Errorf("failed to get reply version and command and reserved, %v", err)
			proxyBindConn.Close()
		}
		reply2.VER, reply2.REP, reply2.RSV = tmp[0], tmp[1], tmp[2]
		if reply2.VER != Version5 {
			errorChan <- fmt.Errorf("unrecognized SOCKS version[%d]", reply.VER)
			proxyBindConn.Close()
		}
		// read address
		serverBoundAddr, _, err := readAddress(proxyBindConn, request.VER)
		if err != nil {
			errorChan <- fmt.Errorf("failed to get reply address, %v", err)
			proxyBindConn.Close()
		}
		reply2.Address = serverBoundAddr
		if reply2.REP != SUCCESSED {
			errorChan <- errors.New("server refuse client request,when second time reply")
			proxyBindConn.Close()
		}
		errorChan <- nil
	}()
	return serverBoundAddr, errorChan, nil
}

// logf Logging is done using the client's errorlog
func (clt *Client) logf() func(format string, args ...interface{}) {
	if clt.ErrorLog == nil {
		return log.Printf
	}
	return clt.ErrorLog.Printf
}
