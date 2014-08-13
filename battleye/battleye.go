package battleye

import (
	"bytes"
	"fmt"
	"hash/crc32"
)

type BEHeader struct {
	MagicBytes []byte
	Crc        []byte
	Spacer     byte
	PacketType byte
}

type BEPacket interface {
	Unmarshal(rawBytes []byte) error
	Marshal() ([]byte, error)
}

func NewBEHeader() *BEHeader {
	return &BEHeader{MagicBytes: []byte("BE"), Crc: []byte{0x0, 0x0, 0x0, 0x0}, Spacer: 0xFF, PacketType: 0x00}
}

func (n *BEHeader) Unmarshal(rawBytes []byte) error {
	length := len(rawBytes)
	if length < 8 {
		return fmt.Errorf("invalid packet header: packet length too small (%d)", length)
	}
	n.MagicBytes = rawBytes[:2]
	if !bytes.Equal(n.MagicBytes, []byte("BE")) {
		return fmt.Errorf("invalid packet header: magic bytes (%s)", n.MagicBytes)
	}
	n.Crc = rawBytes[2:6]
	n.Spacer = rawBytes[6:7][0]
	if n.Spacer != 0xFF {
		return fmt.Errorf("invalid packet header: spacer (0x%x)", n.Spacer)
	}
	n.PacketType = rawBytes[7:8][0]
	if !(n.PacketType == 0x00 || n.PacketType == 0x01 || n.PacketType == 0x02) {
		return fmt.Errorf("invalid packet header: packet type (0x%x)", n.PacketType)
	}
	return nil
}

func (b *BEHeader) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	n, _ := buf.Write(b.MagicBytes)
	length += n
	n, _ = buf.Write(b.Crc)
	length += n
	buf.WriteByte(b.Spacer)
	length++
	buf.WriteByte(b.PacketType)
	length++
	if length != 8 {
		return nil, fmt.Errorf("invalid packet header: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type BEClientLogin struct {
	Header   BEHeader
	Password string
}

func NewBEClientLogin() *BEClientLogin {
	var packet BEClientLogin
	packet.Header = *NewBEHeader()
	packet.Header.PacketType = 0
	packet.Password = "default"
	return &packet
}

func (b *BEClientLogin) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:8])
	if err != nil {
		return err
	}
	b.Password = string(rawBytes[8:])
	return nil
}

func (b *BEClientLogin) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	hash, err := getHash([]byte{b.Header.Spacer, b.Header.PacketType}, []byte(b.Password))
	if err != nil {
		return nil, err
	}
	b.Header.Crc = hash
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	n, _ = buf.WriteString(b.Password)
	length += n
	if length != (8 + len(b.Password)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type BEServerLogin struct {
	Header        BEHeader
	LoginResponse byte
}

func NewBEServerLogin() *BEServerLogin {
	var packet BEServerLogin
	packet.Header = *NewBEHeader()
	packet.Header.PacketType = 0
	packet.LoginResponse = 0
	return &packet
}

func (b *BEServerLogin) Unmarshal(rawBytes []byte) error {
	if len(rawBytes) < 9 {
		return fmt.Errorf("invalid packet response: no login response")
	}
	err := b.Header.Unmarshal(rawBytes[:8])
	if err != nil {
		return err
	}
	b.LoginResponse = rawBytes[8:9][0]
	return nil
}

func (b *BEServerLogin) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	hash, err := getHash([]byte{b.Header.Spacer, b.Header.PacketType}, []byte{b.LoginResponse})
	if err != nil {
		return nil, err
	}
	b.Header.Crc = hash
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.LoginResponse)
	length++
	if length != (8 + 1) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type BEClientCommand struct {
	Header   BEHeader
	Sequence byte
	Command  string
	Retries  uint16
}

func NewBEClientCommand() *BEClientCommand {
	var packet BEClientCommand
	packet.Header = *NewBEHeader()
	packet.Header.PacketType = 1
	packet.Sequence = 0
	packet.Command = ""
	return &packet
}

func (b *BEClientCommand) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:8])
	if err != nil {
		return err
	}
	b.Sequence = rawBytes[8:9][0]
	b.Command = string(rawBytes[9:])
	return nil
}

func (b *BEClientCommand) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	hash, err := getHash([]byte{b.Header.Spacer, b.Header.PacketType, b.Sequence}, []byte(b.Command))
	if err != nil {
		return nil, err
	}
	b.Header.Crc = hash
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.Sequence)
	length++
	n, _ = buf.WriteString(b.Command)
	length += n
	if length != (9 + len(b.Command)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type BEOptionalHeader struct {
	MagicByte       byte
	NumberOfPackets byte
	Index           byte
}

type BEServerCommand struct {
	Header         BEHeader
	Sequence       byte
	OptionalHeader *BEOptionalHeader
	Response       string
}

func NewBEServerCommand() *BEServerCommand {
	var packet BEServerCommand
	packet.Header = *NewBEHeader()
	packet.Header.PacketType = 1
	packet.Sequence = 0
	packet.OptionalHeader = nil
	packet.Response = ""
	return &packet
}

func (b *BEServerCommand) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:8])
	if err != nil {
		return err
	}
	b.Sequence = rawBytes[8:9][0]
	if len(rawBytes) >= 10 {
		if rawBytes[9:10][0] == 0x00 {
			// optional header
			b.OptionalHeader = &BEOptionalHeader{}
			b.OptionalHeader.MagicByte = 0x00
			b.OptionalHeader.NumberOfPackets = rawBytes[10:11][0]
			b.OptionalHeader.Index = rawBytes[11:12][0]
			b.Response = string(rawBytes[12:])
		} else {
			b.Response = string(rawBytes[9:])
		}
	}
	return nil
}

type BEClientMessage struct {
	Header   BEHeader
	Sequence byte
}

func NewBEClientMessage() *BEClientMessage {
	var packet BEClientMessage
	packet.Header = *NewBEHeader()
	packet.Header.PacketType = 2
	packet.Sequence = 0
	return &packet
}

func (b *BEClientMessage) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:8])
	if err != nil {
		return err
	}
	b.Sequence = rawBytes[8:9][0]
	return nil
}

func (b *BEClientMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	hash, err := getHash([]byte{b.Header.Spacer, b.Header.PacketType, b.Sequence})
	if err != nil {
		return nil, err
	}
	b.Header.Crc = hash
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.Sequence)
	length++
	if length != 9 {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

type BEServerMessage struct {
	Header   BEHeader
	Sequence byte
	Message  string
}

func NewBEServerMessage() *BEServerMessage {
	var packet BEServerMessage
	packet.Header = *NewBEHeader()
	packet.Header.PacketType = 2
	packet.Sequence = 0
	packet.Message = ""
	return &packet
}

func (b *BEServerMessage) Unmarshal(rawBytes []byte) error {
	err := b.Header.Unmarshal(rawBytes[:8])
	if err != nil {
		return err
	}
	b.Sequence = rawBytes[8:9][0]
	b.Message = string(rawBytes[9:])
	return nil
}

func (b *BEServerMessage) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	length := 0
	hash, err := getHash([]byte{b.Header.Spacer, b.Header.PacketType, b.Sequence}, []byte(b.Message))
	if err != nil {
		return nil, err
	}
	b.Header.Crc = hash
	wb, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	n, _ := buf.Write(wb)
	length += n
	buf.WriteByte(b.Sequence)
	length++
	n, _ = buf.WriteString(b.Message)
	length += n
	if length != (9 + len(b.Message)) {
		return nil, fmt.Errorf("invalid packet: packet length too small (%d)", length)
	}
	return buf.Bytes(), nil
}

func getHash(bytes ...[]byte) ([]byte, error) {
	hash := crc32.NewIEEE()
	for _, x := range bytes {
		hash.Write(x)
	}
	raw := hash.Sum32()
	return []byte{byte(raw & 0x000000ff), byte(raw & 0x0000ff00 >> 8), byte(raw & 0x00ff0000 >> 16), byte(raw & 0xff000000 >> 24)}, nil
}

func CRC32(bytes ...[]byte) ([]byte, error) {
	hash := crc32.NewIEEE()
	for _, x := range bytes {
		hash.Write(x)
	}
	raw := hash.Sum32()
	return []byte{byte(raw & 0x000000ff), byte(raw & 0x0000ff00 >> 8), byte(raw & 0x00ff0000 >> 16), byte(raw & 0xff000000 >> 24)}, nil

}
