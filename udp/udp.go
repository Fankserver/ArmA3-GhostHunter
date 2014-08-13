package udp

import (
	"bytes"
	"fmt"
	"ghosthunter/battleye"
	"net"
	"sync"
	"time"
)

type UDPClient struct {
	con         *net.UDPConn
	Out         chan battleye.BEPacket        // to server
	CmdIn       chan battleye.BEServerCommand // to client
	MsgIn       chan battleye.BEServerMessage // to client
	Err         chan error                    // error channel
	chk         chan battleye.BEServerCommand // to pending processor
	server      *net.UDPAddr
	cmdCounter  byte
	cmdMutex    *sync.Mutex
	online      bool
	onlineMutex *sync.Mutex
	heartbeat   time.Time
	cfg         *Config
}

type Config struct {
	Server string
	Rconpw string
}

func NewUDPClient(cfg *Config) *UDPClient {
	return &UDPClient{
		Out:         make(chan battleye.BEPacket, 10),
		CmdIn:       make(chan battleye.BEServerCommand, 20),
		MsgIn:       make(chan battleye.BEServerMessage, 20),
		Err:         make(chan error),
		chk:         make(chan battleye.BEServerCommand, 10),
		cmdMutex:    &sync.Mutex{},
		onlineMutex: &sync.Mutex{},
		cfg:         cfg,
	}
}

func (u *UDPClient) Listen() {
	var buf [4096]byte
	var header battleye.BEHeader

Reconnect:
	for {
		// reset counters
		u.cmdMutex.Lock()
		u.cmdCounter = 0
		u.heartbeat = time.Now()
		u.cmdMutex.Unlock()

		u.onlineMutex.Lock()
		u.online = true // todo: this is a hack... it should be false until proven
		u.onlineMutex.Unlock()

		// (re)connect
		server, err := net.ResolveUDPAddr("udp", u.cfg.Server)
		if err != nil {
			u.Err <- err
			return
		}
		u.server = server

		u.con, err = net.DialUDP("udp", nil, u.server)
		if err != nil {
			u.Err <- err
			time.Sleep(15 * time.Second)
			continue
		}

		// read deadline
		u.con.SetReadDeadline(time.Now().Add(15 * time.Second))

		// login
		newPacket := battleye.NewBEClientLogin()
		newPacket.Password = u.cfg.Rconpw
		u.Out <- newPacket

		// listen for incoming packets
		for {
			n, addr, err := u.con.ReadFromUDP(buf[:])
			u.con.SetReadDeadline(time.Now().Add(45 * time.Second))
			u.onlineMutex.Lock()
			online := u.online
			if !online {
				err = fmt.Errorf("not online anymore")
			}
			u.onlineMutex.Unlock()
			if err != nil || !online {
				u.Err <- err
				u.con.Close()
				continue Reconnect
			} else {
				if addr.String() == u.server.String() {
					err = header.Unmarshal(buf[:n])
					if err == nil {
						crcCheck, _ := battleye.CRC32(buf[6:n])
						//log.Printf("%x %x\n", crcCheck, header.Crc)
						if !bytes.Equal(crcCheck, header.Crc) {
							continue
						}
						switch {
						case header.PacketType == 0:
							// BE login packet
							packet := battleye.NewBEServerLogin()
							err := packet.Unmarshal(buf[:n])
							if err == nil {
								if packet.LoginResponse == 1 {
									u.onlineMutex.Lock()
									u.online = true
									u.onlineMutex.Unlock()
									u.Err <- fmt.Errorf("logged in")
								} else {
									u.Err <- fmt.Errorf("invalid password")
									return
								}
							}
						case header.PacketType == 1:
							// BE command packet
							packet := battleye.NewBEServerCommand()
							err := packet.Unmarshal(buf[:n])
							if err == nil {
								//log.Println("new cmd", packet)
								u.CmdIn <- *packet
								u.chk <- *packet
							}
						case header.PacketType == 2:
							// BE server message
							packet := battleye.NewBEServerMessage()
							err := packet.Unmarshal(buf[:n])
							if err == nil {
								u.MsgIn <- *packet
								response := battleye.NewBEClientMessage()
								response.Sequence = packet.Sequence
								u.Out <- response
							}
						}
					}
				}
			}
		}
	}
}

func (u *UDPClient) ProcessPendingPackets() {
	pending := make([]*[]byte, 256)
	pendingRetries := make([]uint16, 256)
	ticker := time.Tick(1 * time.Second)
	beat := battleye.NewBEClientCommand()
	beat.Command = ""
	fails := 0
	for {
		select {
		case p := <-u.Out:
			bytes, err := p.Marshal()
			if err == nil {
				// check packet type
				if bytes[7] == 0x01 {
					// modify command sequence
					u.cmdMutex.Lock()
					if u.cmdCounter > 255 {
						u.cmdCounter = 0
					}
					//u.Err <- fmt.Errorf("debug: packet sequence %x", u.cmdCounter)
					bytes[8] = u.cmdCounter
					u.cmdCounter += 1
					u.cmdMutex.Unlock()
					// recalculate crc32
					newCRC, _ := battleye.CRC32(bytes[6:])
					bytes[2] = newCRC[0]
					bytes[3] = newCRC[1]
					bytes[4] = newCRC[2]
					bytes[5] = newCRC[3]
					// add new packet to list of pending packets
					pending[bytes[8]] = &bytes
				} else {
					u.con.Write(bytes)
					//u.con.SetReadDeadline(time.Now().Add(30 * time.Second))
				}
			}
		case x := <-u.chk:
			// check whether this is a reply
			// of nrcon to an issued command
			for k, v := range pending {
				if v != nil {
					//log.Printf("%d %d", (*v)[8], x.Sequence)
					if (*v)[8] == x.Sequence {
						pending[k] = nil
					}
				}
			}
		case <-ticker:
			// process all pending packets
			for k, v := range pending {
				if v != nil {
					if pendingRetries[k] < 5 {
						pendingRetries[k] += 1
						//log.Printf("(re)sending %x", *v)
						u.con.Write(*v)
						//u.con.SetReadDeadline(time.Now().Add(30 * time.Second))
					} else {
						u.Err <- fmt.Errorf("udp could not send packet in time (%x)", *pending[k])
						fails++
						pendingRetries[k] = 0
						pending[k] = nil
						if fails >= 5 {
							fails = 0
							u.Err <- fmt.Errorf("too many failed send attempts")
							u.onlineMutex.Lock()
							u.online = false
							u.onlineMutex.Unlock()
						}
					}
				}
			}
			u.onlineMutex.Lock()
			if u.online {
				// send a heartbeat if no other commands have been issued since 30 seconds
				diff := time.Since(u.heartbeat)
				if diff >= 30*time.Second {
					u.heartbeat = time.Now()
					u.Out <- beat
				}
			}
			u.onlineMutex.Unlock()
		}
	}

}

func (u *UDPClient) KickPlayerById(id int16, reason string) error {
	newPacket := battleye.NewBEClientCommand()
	cmd := ""
	if reason != "" {
		cmd = fmt.Sprintf("kick %d %s", id, reason)
	} else {
		cmd = fmt.Sprintf("kick %d", id)
	}
	newPacket.Command = cmd

	u.Out <- newPacket

	return nil
}
