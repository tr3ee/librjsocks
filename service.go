package librjsocks

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

/*
 Event represents the event currently obtained from the auth-server.
 the event table defined below.
*/
type Event int

/*
 all Event defined here.
*/
const (
	EventError = Event(iota)
	EventIdle
	EventRespIdentity
	EventRespMd5Chall
	EventSuccess
	EventFailure
)

func (e Event) String() string {
	switch e {
	case EventRespIdentity:
		return "RequestIdentity"
	case EventRespMd5Chall:
		return "RequestMd5Chall"
	case EventSuccess:
		return "Success"
	case EventFailure:
		return "Failure"
	case EventIdle:
		return "Idle"
	case EventError:
		return "Error"
	default:
		return fmt.Sprintf("unknown(%d)\n", e)
	}
}

var ErrFailure = fmt.Errorf("auth failed")

const idleTimeout = 28 * time.Second

/*
 Service defines all the data required in the authentication process.
 You can get an instance by calling NewService().

 the exported methods are listed below:
 ----------------------------------------------
 * Run    | Main Entry, start a auth-service
 * Ads    | get the advertisement from auth server
 * Stat   | get the current service's status
 * Notify | register a event notifier
 * Close  | stop & clean up
 ----------------------------------------------

 note: currently, it's *NOT* concurrent-safe.
*/
type Service struct {
	username  []byte
	password  []byte
	nwinfo    *NwAdapterInfo
	lastPkt   gopacket.Packet
	lastEvent Event
	pktSrc    *gopacket.PacketSource
	pktChan   chan gopacket.Packet
	handle    *Handle
	eventChan chan<- Event
	ads       string
	echoNo    uint32
	echoKey   uint32
	closed    BOOL
	running   BOOL
}

// NewService returns a new instance of auth-service
func NewService(user, pass string, nwAdapterinfo *NwAdapterInfo) (*Service, error) {
	if nwAdapterinfo == nil {
		return nil, fmt.Errorf("network interface is nil")
	}
	handle, err := NewHandle(nwAdapterinfo.DeviceName, nwAdapterinfo.Mac)
	if err != nil {
		return nil, err
	}
	srv := &Service{
		username: []byte(user),
		password: []byte(pass),
		nwinfo:   nwAdapterinfo,
		pktSrc:   gopacket.NewPacketSource(handle.PcapHandle, layers.LayerTypeEthernet),
		pktChan:  make(chan gopacket.Packet, 1024),
		handle:   handle,
	}
	return srv, nil
}

func (s *Service) Run() error {
	if !s.running.True() {
		return fmt.Errorf("service is already running")
	}
	defer s.running.False()
	go s.prePacket()
	s.handleEvent(EventIdle)
	for !s.closed.RLock() {
		e, err := s.nextEvent()
		if s.eventChan != nil {
			select {
			case s.eventChan <- e:
			default:
			}
		}
		if err != nil {
			return err
		}
		if err := s.handleEvent(e); err != nil {
			return err
		}
		s.closed.RUnlock()
	}
	return nil
}

func (s *Service) Ads() string {
	return s.ads
}

func (s *Service) Close() {
	/*TODO: close all resources*/
	for !s.closed.True() {
		time.Sleep(500 * time.Millisecond)
	}
	close(s.eventChan)
	s.handle.Close()
}

func (s *Service) LastEvent() Event {
	return s.lastEvent
}

func (s *Service) Notify(ch chan<- Event) error {
	if s.eventChan == nil {
		s.eventChan = ch
	} else {
		return fmt.Errorf("notify channel is registered already")
	}
	return nil
}

func (s *Service) prePacket() {
	for packet := range s.pktSrc.Packets() {
		// am I the target?
		_eth := packet.Layer(layers.LayerTypeEthernet)
		if _eth == nil {
			continue
		}
		eth := _eth.(*layers.Ethernet)
		if bytes.Compare(eth.SrcMAC, s.nwinfo.Mac) == 0 || (bytes.Compare(eth.DstMAC, s.nwinfo.Mac) != 0 && bytes.Compare(eth.DstMAC, MultiCastAddr) != 0) {
			continue
		}
		// try to decode as EAP layer.
		eap := packet.Layer(layers.LayerTypeEAP)
		if s.closed.RLock() {
			s.closed.RUnlock()
			break
		}
		if eap != nil {
			s.pktChan <- packet
		}
		s.closed.RUnlock()
	}
}

func (s *Service) nextEvent() (Event, error) {
	var pkt gopacket.Packet
	select {
	case pkt = <-s.pktChan:
		s.lastPkt = pkt
		eap := pkt.Layer(layers.LayerTypeEAP).(*layers.EAP)
		switch eap.Code {
		case layers.EAPCodeRequest:
			switch eap.Type {
			case layers.EAPTypeIdentity:
				return EventRespIdentity, nil
			case layers.EAPTypeOTP:
				return EventRespMd5Chall, nil
			}
		case layers.EAPCodeSuccess:
			return EventSuccess, nil
		case layers.EAPCodeFailure:
			return EventFailure, nil
		}
	case <-time.After(idleTimeout):
		return EventIdle, nil
	}
	return EventError, nil
}

func (s *Service) parseExdata(data []byte) ([]byte, uint32, error) {
	r := bufio.NewReader(bytes.NewReader(data))
	ads, err := parseMTLV(r)
	if err != nil {
		return nil, 0, err
	}
	utf8Ads, err := toUTF8(ads.Buffer)
	if err == nil {
		ads.Buffer = utf8Ads
	}
	_, err = r.Discard(0x7B + 6)
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 4)
	_, err = r.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	symEncode(buf)
	key := binary.BigEndian.Uint32(buf)
	return ads.Buffer, key, nil
}

func (s *Service) handleEvent(e Event) error {
	defer func() { s.lastEvent = e }()
	switch e {
	case EventRespIdentity:
		eth := s.lastPkt.Layer(layers.LayerTypeEthernet).(*layers.Ethernet)
		eap := s.lastPkt.Layer(layers.LayerTypeEAP).(*layers.EAP)
		s.handle.SetDstMacAddr(eth.SrcMAC)
		if err := s.handle.SendResponseIdentity(eap.Id, s.username); err != nil {
			return err
		}
	case EventRespMd5Chall:
		eap := s.lastPkt.Layer(layers.LayerTypeEAP).(*layers.EAP)
		if eap.TypeData[0] == '\x10' && len(eap.TypeData) >= 17 {
			seed := eap.TypeData[1:17]
			if err := s.handle.SendResponseMD5Chall(eap.Id, seed, s.username, s.password); err != nil {
				return err
			}
		}
	case EventSuccess:
		eap := s.lastPkt.Layer(layers.LayerTypeEAP).(*layers.EAP)
		if len(eap.Contents) > 4 {
			ads, key, err := s.parseExdata(eap.Contents[4:])
			if err != nil {
				return err
			}
			s.ads = string(ads)
			s.echoKey = key
			s.echoNo = uint32(0x102b)
			go refreshIP(s.nwinfo.AdapterName)
		} else {
			return fmt.Errorf("packet corrupted: no enough data to parse on EventSuccess")
		}
	case EventIdle:
		if s.lastEvent == EventSuccess || s.lastEvent == EventIdle {
			if err := s.handle.SendEchoPkt(s.echoNo, s.echoKey); err != nil {
				return err
			}
			s.echoNo++
		} else {
			if err := s.handle.SendStartPkt(); err != nil {
				return err
			}
		}
	case EventFailure:
		return ErrFailure
	case EventError:
		return fmt.Errorf("EventError: last-packet: %s", s.lastPkt)
	}
	return nil
}
