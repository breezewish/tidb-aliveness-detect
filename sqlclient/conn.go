package sqlclient

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/siddontang/go-mysql/mysql"
	"github.com/siddontang/go-mysql/packet"
)

const (
	dialTimeout = 3 * time.Second
	readTimeout = 3 * time.Second
)

func getNetProto(addr string) string {
	proto := "tcp"
	if strings.Contains(addr, "/") {
		proto = "unix"
	}
	return proto
}

type HandshakePacket struct {
	ServerVersion   string
	ConnectionIDU32 uint32
	CapabilityFlag  uint32
}

func readN(b *bytes.Buffer, n int) ([]byte, error) {
	buf := make([]byte, n)
	n2, err := b.Read(buf)
	if err != nil {
		return nil, err
	}
	if n2 < n {
		return nil, io.EOF
	}
	return buf, nil
}

func TryConnect(addr string) (*HandshakePacket, error) {
	proto := getNetProto(addr)
	rawConn, err := net.DialTimeout(proto, addr, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer rawConn.Close()

	_ = rawConn.SetReadDeadline(time.Now().Add(readTimeout))

	c := packet.NewConn(rawConn)
	p := &HandshakePacket{}

	// The following handshake process is modified from https://github.com/siddontang/go-mysql/blob/master/mysql/const.go .
	// See https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html for protocol details.

	data, err := c.ReadPacket()
	if err != nil {
		return nil, err
	}

	buf := bytes.NewBuffer(data)
	//r := bufio.NewReader(bytes.NewReader(data))

	// protocol version
	b, err := readN(buf, 1)
	if err != nil {
		return nil, err
	}
	if b[0] == mysql.ERR_HEADER {
		return nil, fmt.Errorf("read initial handshake error")
	}
	if b[0] < mysql.MinProtocolVersion {
		return nil, fmt.Errorf("invalid protocol version %d", data[0])
	}

	// server version
	b, err = buf.ReadBytes(0x00)
	if err != nil {
		return nil, err
	}
	if len(b) > 1 {
		p.ServerVersion = string(b[:len(b)-1])
	}

	// thread id
	b, err = readN(buf, 4)
	if err != nil {
		return nil, err
	}
	p.ConnectionIDU32 = binary.LittleEndian.Uint32(b)

	// auth-plugin-data-part-1, filler
	b, err = readN(buf, 8+1)
	if err != nil {
		return nil, err
	}

	// capability_flags_1
	b, err = readN(buf, 2)
	if err != nil {
		return nil, err
	}
	p.CapabilityFlag = uint32(binary.LittleEndian.Uint16(b))
	if p.CapabilityFlag&mysql.CLIENT_PROTOCOL_41 == 0 {
		return nil, fmt.Errorf("expect protocol 41")
	}

	if buf.Len() > 0 {
		// character_set
		_, err = readN(buf, 1)
		if err != nil {
			return nil, err
		}

		// status_flags
		_, err = readN(buf, 2)
		if err != nil {
			return nil, err
		}

		// capability_flags_2
		b, err = readN(buf, 2)
		if err != nil {
			return nil, err
		}
		p.CapabilityFlag |= uint32(binary.LittleEndian.Uint16(b)) << 16
		// auth_plugin_data_len
		// reserved
		_, err = readN(buf, 11)
		if err != nil {
			return nil, err
		}
		// auth-plugin-data-part-2
		_, err = readN(buf, 13)
		if err != nil {
			return nil, err
		}
	}

	return p, nil
}

