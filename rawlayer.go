package librjsocks

import "github.com/google/gopacket"

var fillLayer = rawLayer{fillbuf}

var rawLayerType = gopacket.RegisterLayerType(0x1337, gopacket.LayerTypeMetadata{Name: "RawLayer", Decoder: gopacket.DecodeFunc(decodeRawLayer)})

type rawLayer struct {
	RawBytes []byte
}

func (r *rawLayer) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	bytes, err := b.AppendBytes(len(r.RawBytes))
	if err != nil {
		return err
	}
	copy(bytes, r.RawBytes)
	return nil
}

func (r *rawLayer) LayerType() gopacket.LayerType {
	return rawLayerType
}

func decodeRawLayer(data []byte, p gopacket.PacketBuilder) error {
	return nil
}

var fillbuf = []byte{
	// dhcp layer
	0xff, 0xff, 0x37, 0x77, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xfd, 0x36,
	// padding layer
	0x00, 0x00, 0x13, 0x11, 0x38, 0x30, 0x32, 0x31, 0x78, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x04, 0x0a, 0x00, 0x02, 0x00, 0x00, 0x00, 0x13, 0x11, 0x01, 0x8c, 0x1a,
	0x28, 0x00, 0x00, 0x13, 0x11, 0x17, 0x22, 0x36, 0x38, 0x44, 0x43, 0x31, 0x32, 0x33, 0x42, 0x37,
	0x45, 0x42, 0x32, 0x33, 0x39, 0x46, 0x32, 0x33, 0x41, 0x38, 0x43, 0x30, 0x30, 0x30, 0x33, 0x38,
	0x38, 0x34, 0x39, 0x38, 0x36, 0x33, 0x39, 0x1a, 0x0c, 0x00, 0x00, 0x13, 0x11, 0x18, 0x06, 0x00,
	0x00, 0x00, 0x00, 0x1a, 0x0e, 0x00, 0x00, 0x13, 0x11, 0x2d, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x1a, 0x08, 0x00, 0x00, 0x13, 0x11, 0x2f, 0x02, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x35,
	0x03, 0x01, 0x1a, 0x18, 0x00, 0x00, 0x13, 0x11, 0x36, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x18, 0x00, 0x00, 0x13, 0x11,
	0x38, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x86,
	0x13, 0x4c, 0x1a, 0x88, 0x00, 0x00, 0x13, 0x11, 0x4d, 0x82, 0x36, 0x38, 0x64, 0x63, 0x31, 0x32,
	0x33, 0x62, 0x30, 0x37, 0x65, 0x62, 0x32, 0x33, 0x39, 0x66, 0x32, 0x33, 0x61, 0x38, 0x30, 0x64,
	0x63, 0x66, 0x32, 0x35, 0x38, 0x37, 0x35, 0x64, 0x30, 0x35, 0x37, 0x37, 0x30, 0x63, 0x37, 0x32,
	0x31, 0x65, 0x34, 0x35, 0x36, 0x34, 0x35, 0x65, 0x35, 0x33, 0x37, 0x61, 0x62, 0x33, 0x35, 0x31,
	0x62, 0x62, 0x36, 0x33, 0x31, 0x35, 0x35, 0x61, 0x65, 0x31, 0x36, 0x32, 0x36, 0x31, 0x36, 0x37,
	0x65, 0x62, 0x30, 0x39, 0x32, 0x32, 0x33, 0x65, 0x32, 0x61, 0x30, 0x61, 0x37, 0x38, 0x30, 0x33,
	0x31, 0x31, 0x36, 0x31, 0x61, 0x63, 0x30, 0x39, 0x64, 0x61, 0x32, 0x64, 0x63, 0x30, 0x37, 0x33,
	0x36, 0x39, 0x33, 0x61, 0x34, 0x66, 0x35, 0x61, 0x32, 0x39, 0x32, 0x38, 0x36, 0x37, 0x35, 0x31,
	0x66, 0x39, 0x37, 0x66, 0x34, 0x64, 0x30, 0x34, 0x36, 0x38, 0x1a, 0x28, 0x00, 0x00, 0x13, 0x11,
	0x39, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x1a, 0x48, 0x00, 0x00, 0x13, 0x11, 0x54, 0x42, 0x48, 0x55, 0x53, 0x54, 0x4d, 0x4f,
	0x4f, 0x4e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1a, 0x08, 0x00, 0x00, 0x13, 0x11,
	0x55, 0x02, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x62, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}
