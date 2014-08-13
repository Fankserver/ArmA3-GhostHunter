/*
	Copyright © 2014, Niko "nano2k" Bochan.
	Licensed under the Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International Public License
	http://creativecommons.org/licenses/by-nc-nd/4.0/
*/

package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"ghosthunter/api"
	"ghosthunter/battleye"
	"ghosthunter/udp"
	//"github.com/alecthomas/geoip"
	"github.com/daviddengcn/go-colortext"
	"io/ioutil"
	"log"
	//"net"
	"net/http"
	//_ "net/http/pprof"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

var (
	client *udp.UDPClient
)

const (
	HTTP_API_URL = "http://xxx.xxx.fankservercdn.com/player.api.html?BattlEyeGUID=%s"
)

type Detection struct {
	Index    uint16
	Reaction byte
	Format   string
}

type Chatfilter struct {
	Filename   string
	Detections []Detection
}

func NewChatfilter(file string) *Chatfilter {
	return &Chatfilter{Filename: file}
}

func main() {
	// enable usage of all cpu cores
	runtime.GOMAXPROCS(runtime.NumCPU())

	// profiling
	//go func() {
	//log.Println(http.ListenAndServe("localhost:6060", nil))
	//}()

	// json config
	configpath := flag.String("config", "default.json", "json config file")
	flag.Parse()
	*configpath = fmt.Sprintf("config/%s", *configpath)
	// json parse
	file, e := ioutil.ReadFile(*configpath)
	if e != nil {
		log.Fatalf("config error: %v\n", e)
		return
	}

	var config udp.Config
	perr := json.Unmarshal(file, &config)
	if perr != nil {
		log.Fatalf("config error (%s): %s", *configpath, perr)
		return
	}

	// filter
	cfilter := NewChatfilter("filter/chat.txt")
	err := loadChatFilter(cfilter)
	if err != nil {
		log.Println(err)
	}

	//log.Printf("%v", config)

	// channels
	kickLog, banLog, chatLog, packets, errors := make(chan string, 5), make(chan string, 5), make(chan string, 5), make(chan string, 5), make(chan error, 5)

	client = udp.NewUDPClient(&config)
	go client.ProcessPendingPackets()
	go client.Listen()

	go concatPackets(client.CmdIn, packets)

	for i := 0; i < 5; i++ {
		go handleMessages(client.MsgIn, chatLog, kickLog, banLog, cfilter)
	}
	go handleCommands(client, packets, kickLog, banLog, errors)

	go console()

	// log files
	fErr, err := os.OpenFile("logs/error.log", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Println(err)
	}
	defer fErr.Close()

	fKick, err := os.OpenFile("logs/kick.log", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Println(err)
	}
	defer fKick.Close()

	fBan, err := os.OpenFile("logs/ban.log", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Println(err)
	}
	defer fBan.Close()

	fChat, err := os.OpenFile("logs/chat.log", os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		log.Println(err)
	}
	defer fChat.Close()

	for {
		select {
		case e := <-errors:
			fErr.WriteString(time.Now().String() + " " + e.Error() + "\n")
			ct.ChangeColor(ct.Cyan, true, ct.Black, false)
			log.Println(e)
			ct.ResetColor()
		case e := <-client.Err:
			fErr.WriteString(time.Now().String() + " " + e.Error() + "\n")
			ct.ChangeColor(ct.Cyan, true, ct.Black, false)
			log.Println(e)
			ct.ResetColor()
		case k := <-kickLog:
			fKick.WriteString(time.Now().String() + " " + k + "\n")
			ct.ChangeColor(ct.Red, true, ct.Black, false)
			log.Println(k)
			ct.ResetColor()
		case c := <-chatLog:
			fChat.WriteString(time.Now().String() + " " + c + "\n")
			//log.Println(c)
		case b := <-banLog:
			fBan.WriteString(time.Now().String() + " " + b + "\n")
			ct.ChangeColor(ct.Red, true, ct.Black, false)
			log.Println(b)
			ct.ResetColor()
		}
	}
}

func console() {
	reader := bufio.NewReader(os.Stdin)

	for {
		line, _ := reader.ReadString('\n')
		if strings.HasPrefix(line, "kick") {
			rawstr := strings.Fields(line)
			if len(rawstr) == 2 {
				newpkt := battleye.NewBEClientCommand()
				newpkt.Command = fmt.Sprintf("kick %s", rawstr[1])
				client.Out <- newpkt
			} else if len(rawstr) == 3 {
				//client.KickPlayerById(id int16, reason string)
				newpkt := battleye.NewBEClientCommand()
				newpkt.Command = fmt.Sprintf("kick %s %s", rawstr[1], rawstr[2])
				client.Out <- newpkt
			}
		} else if strings.HasPrefix(line, "ping") {
			newpkt := battleye.NewBEClientCommand()
			newpkt.Command = fmt.Sprintf("maxping")
			client.Out <- newpkt
		} else if strings.HasPrefix(line, "pl") {
			newpkt := battleye.NewBEClientCommand()
			newpkt.Command = fmt.Sprintf("players")
			client.Out <- newpkt
		}
	}
}

func handleMessages(c chan battleye.BEServerMessage, chatLog, kickLog, banLog chan string, filter *Chatfilter) {
	/*geo, err := geoip.New()
	if err != nil {
		log.Fatalln(err)
	}*/

	// regular expressions
	reParseMsg := regexp.MustCompile(`^\((\w+)\) (.*): (.*)$`)
	reParseConnected := regexp.MustCompile(`^Player #([0-9]{1,3}) (.*) \((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{4,5})\) connected$`)
	reParseLogin := regexp.MustCompile(`^Player #([0-9]{1,3}) (.*) - GUID: ([a-f0-9]{32}) \(unverified\)$`)
	reParseKicked := regexp.MustCompile(`Player #(\d+) (.*) \((\w{32})\) has been kicked by (.+): (.+)`)

	for {
		select {
		case p := <-c:
			rawstring := p.Message
			switch {
			case strings.HasSuffix(rawstring, "(unverified)"):
				parsedstrings := reParseLogin.FindStringSubmatch(rawstring)
				if len(parsedstrings) == 4 {
					log.Printf("new player (#%s %s %s)", parsedstrings[1], parsedstrings[2], parsedstrings[3])
					//request to api

				} else {
					client.Err <- fmt.Errorf("error parsing new player! (%s)", rawstring)
				}
			case strings.HasSuffix(rawstring, "connected"):
				result := reParseConnected.FindStringSubmatch(rawstring)
				if len(result) == 5 {
					// get player number
					/*tmp, err := strconv.Atoi(result[1])
					number := int16(tmp)
					if err != nil {
						number = int16(-1)
					}

					// check country
					country := geo.Lookup(net.ParseIP(result[3]))
					switch {
					case country == nil:
						log.Printf("%d %s\n", number, "Unknown")
					case country.Short == "DE":
						fallthrough
					case country.Short == "AT":
						fallthrough
					case country.Short == "CH":
						fallthrough
					case country.Short == "LU":
						fallthrough
					case false:
						//log.Printf("%d %s\n", number, country)
					default:
						//client.KickPlayerById(number, "Country Restriction")
						//log.Printf("%d %s\n", number, country)
					}*/
				}
			case strings.HasPrefix(rawstring, "("):
				ct.ChangeColor(ct.Green, true, ct.Black, false)
				log.Printf("chatmsg (%s)", rawstring)
				ct.ResetColor()
				if filter != nil {
					for _, v := range filter.Detections {
						match, err := regexp.MatchString(v.Format, rawstring)
						if err != nil {
							client.Err <- err
							continue
						}
						if match {
							parsedstrings := reParseMsg.FindStringSubmatch(rawstring)
							if len(parsedstrings) == 4 {
								switch v.Reaction {
								case 1:
									chatLog <- fmt.Sprintf("#%d %s", v.Index, rawstring)
								case 2:
									log.Printf("detection #%d %s\n", v.Index, rawstring)
								case 3:
									log.Printf("detection #%d %s\n", v.Index, rawstring)
									chatLog <- fmt.Sprintf("#%d %s", v.Index, rawstring)
								case 4:
									log.Printf("detection #%d %s %s\n", v.Index, rawstring, "[SIMULATED SILENT KICK]")
									chatLog <- fmt.Sprintf("#%d %s", v.Index, rawstring)
								case 5:
									// todo kick
									kickLog <- fmt.Sprintf("#%d %s", v.Index, rawstring)
								case 6:
									// todo kick
									log.Printf("detection #%d %s\n", v.Index, rawstring)
								case 7:
									// todo kick
									log.Printf("detection #%d %s\n", v.Index, rawstring)
									kickLog <- fmt.Sprintf("#%d %s", v.Index, rawstring)
								case 8:
									//todo ban
									log.Printf("detection #%d %s\n", v.Index, rawstring)
									banLog <- fmt.Sprintf("#%d %s", v.Index, rawstring)
								}
							} else {
								client.Err <- fmt.Errorf("error parsing chat message! (%s)", rawstring)
							}
						}
					}
				}
			default:
				parsed := reParseKicked.MatchString(rawstring)
				if parsed {
					kickLog <- fmt.Sprintf("#SVR %s", rawstring)
				} else {
					log.Printf("svmsg (%s)", rawstring)
				}
			}
		}
	}
}

func concatPackets(c chan battleye.BEServerCommand, out chan string) {
	packetbuffer := make([][]string, 256)

	for i := range packetbuffer {
		packetbuffer[i] = make([]string, 100)
	}

	//ticker := time.Tick(5 * time.Second)
	for {
		select {
		case p := <-c:
			if p.OptionalHeader != nil {
				if packetbuffer[p.Sequence][0] == "" {
					packetbuffer[p.Sequence][0] = "0"
				}

				packetbuffer[p.Sequence][p.OptionalHeader.Index+1] = p.Response

				// increment packet counter
				i, _ := strconv.Atoi(packetbuffer[p.Sequence][0])
				ctr := byte(i)
				ctr++

				if ctr >= p.OptionalHeader.NumberOfPackets {
					// we do not need to wait any longer because
					// apparently all packets have arrived
					var result string = ""
					for i := byte(1); i <= p.OptionalHeader.NumberOfPackets; i++ {
						result += packetbuffer[p.Sequence][i]
					}
					out <- result
					for i := byte(1); i <= p.OptionalHeader.NumberOfPackets; i++ {
						packetbuffer[p.Sequence][i] = ""
					}
					ctr = 0
				}

				packetbuffer[p.Sequence][0] = strconv.Itoa(int(ctr))

			} else {
				out <- p.Response
			}
			//case <-ticker:
			// cleanup incomplete packets
		}
	}
}

func handleCommands(client *udp.UDPClient, c chan string, kickLog, banLog chan string, errors chan error) {
	reParsePlayer := regexp.MustCompile(`(\d+)[ ]+((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d{4,5})[ ]+(-?\d+)[ ]+((\w{32})(\([^)]+\))|-)[ ]+(.*)`)
	/*geo, err := geoip.New()
	if err != nil {
		log.Fatalln(err)
	}*/
	for {
		select {
		case response := <-c:
			switch {
			case strings.HasPrefix(response, "Players on server:"):
				response = strings.TrimPrefix(response, "Players on server:\n[#] [IP Address]:[Port] [Ping] [GUID] [Name]\n--------------------------------------------------")
				rawslice := strings.Split(response, "\n")
				for _, element := range rawslice {
					result := reParsePlayer.FindStringSubmatch(element)
					if len(result) == 9 {
						// get player number
						/*tmp, err := strconv.Atoi(result[1])
						number := int16(tmp)
						if err != nil {
							number = int16(-1)
						}

						// check country
						country := geo.Lookup(net.ParseIP(result[3]))
						switch {
						case country == nil:
							log.Printf("%d %s\n", number, "Unknown")
						case country.Short == "DE":
							fallthrough
						case country.Short == "AT":
							fallthrough
						case country.Short == "CH":
							fallthrough
						case country.Short == "LU":
							fallthrough
						case false:
							//log.Printf("%d %s\n", number, country)
						default:
							//client.KickPlayerById(number, "Country Restriction")
							//log.Printf("%d %s\n", number, country)
						}*/

					}
				}
			default:
				ct.ChangeColor(ct.Magenta, true, ct.Black, false)
				log.Printf("svcmd (%s)", response)
				ct.ResetColor()
			}
		}
	}
}

func getPlayerRecord(beguid string) (*api.APIResponse, error) {
	resp, err := http.Get(fmt.Sprintf(HTTP_API_URL, beguid))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var response api.APIResponse
	err = json.Unmarshal(body, &response)
	if err == nil {
		return &response, nil
	} else {
		return nil, err
	}
}

func loadChatFilter(filter *Chatfilter) error {
	if filter != nil {
		content, err := ioutil.ReadFile(filter.Filename)
		if err != nil {
			return err
		}
		lines := strings.Split(string(content), "\n")
		detections := make([]Detection, len(lines))
		for i, v := range lines {
			raw := strings.Fields(v)
			if len(raw) == 2 {
				tmp := &Detection{}
				tmp.Index = uint16(i)
				v1, err := strconv.ParseUint(raw[0], 0, 8)
				if err != nil {
					tmp.Reaction = 1
				} else {
					tmp.Reaction = byte(v1)
				}
				tmp.Format = raw[1]
				detections[i] = *tmp
			}
		}
		filter.Detections = detections
		return nil
	}
	return fmt.Errorf("Chatfilter is nil")
}
