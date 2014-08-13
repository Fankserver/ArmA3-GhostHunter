package remotecall

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type RCPacket interface {
	Unmarshal(rawBytes []byte) error
	Marshal() ([]byte, error)
}

type RCHeader struct {
	MagicBytes []byte
	Version    byte
	Spacer     byte
}

func NewRCHeader() *RCHeader {
	return &RCHeader{MagicBytes: []byte("RC"), Version: 0x01, Spacer: 0xFF}
}

func (n *RCHeader) Unmarshal(rawBytes []byte) error {
	length := len(rawBytes)
	if length != 4 {
		return fmt.Errorf("invalid packet header: packet length mismatch (%d)", length)
	}
	n.MagicBytes = rawBytes[:2]
	if !bytes.Equal(n.MagicBytes, []byte("RC")) {
		return fmt.Errorf("invalid packet header: magic bytes (%s)", n.MagicBytes)
	}
	n.Version = rawBytes[2:3][0]
	n.Spacer = rawBytes[3:4][0]
	if n.Spacer != 0xFF {
		return fmt.Errorf("invalid packet header: spacer (0x%x)", n.Spacer)
	}
	return nil
}

func (b *RCHeader) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	n, _ := buf.Write(b.MagicBytes)
	length += n
	buf.WriteByte(b.Version)
	length++
	buf.WriteByte(b.Spacer)
	length++
	if length != 4 {
		return nil, fmt.Errorf("invalid packet header: packet length mismatch (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCClientHandshake struct {
	Header     RCHeader
	PacketType byte
	Password   string
}

func NewRCClientHandshake() *RCClientHandshake {
	var packet RCClientHandshake
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x00
	packet.Password = "default"
	return &packet
}

func (b *RCClientHandshake) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Password = string(rawBytes[5:])
	return nil
}

func (b *RCClientHandshake) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	n, _ = buf.WriteString(b.Password)
	length += n
	if length != (4 + len(b.Password)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCServerHandshake struct {
	Header     RCHeader
	PacketType byte
	Result     byte
}

func NewRCServerHandshake() *RCServerHandshake {
	var packet RCServerHandshake
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x01
	packet.Result = 0x00
	return &packet
}

func (b *RCServerHandshake) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Result = rawBytes[5:6][0]
	return nil
}

func (b *RCServerHandshake) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	buf.WriteByte(b.Result)
	length += 1
	if length != 6 {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCClientQuery struct {
	Header     RCHeader
	PacketType byte
	Content    string
}

func NewRCClientQuery() *RCClientQuery {
	var packet RCClientQuery
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x10
	packet.Content = ""
	return &packet
}

func (b *RCClientQuery) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.Content = string(rawBytes[5:])
	return nil
}

func (b *RCClientQuery) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	n, _ = buf.WriteString(b.Content)
	length += n
	if length != (4 + len(b.Content)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCServerQuery struct {
	Header     RCHeader
	PacketType byte
	QueryID    uint16
}

func NewRCServerQuery() *RCServerQuery {
	var packet RCServerQuery
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x11
	packet.QueryID = 0
	return &packet
}

func (b *RCServerQuery) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.QueryID = binary.LittleEndian.Uint16(rawBytes[5:7])
	return nil
}

func (b *RCServerQuery) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, b.QueryID)
	length += n
	if length != 7 {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type RCServerQueryResult struct {
	Header     RCHeader
	PacketType byte
	QueryID    uint16
	Content    string
}

func NewRCServerQueryResult() *RCServerQueryResult {
	var packet RCServerQueryResult
	packet.Header = *NewRCHeader()
	packet.PacketType = 0x12
	packet.QueryID = 0
	packet.Content = ""
	return &packet
}

func (b *RCServerQueryResult) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:4])
	if err != nil {
		return err
	}
	b.PacketType = rawBytes[4:5][0]
	b.QueryID = binary.LittleEndian.Uint16(rawBytes[5:7])
	b.Content = string(rawBytes[7:])
	return nil
}

func (b *RCServerQueryResult) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.PacketType)
	length += 1
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, b.QueryID)
	length += n
	n, _ = buf.WriteString(b.Content)
	length += n
	if length != (7 + len(b.Content)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}
