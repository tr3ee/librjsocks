package librjsocks

import "net"

type NwAdapterInfo struct {
	AdapterName string
	DeviceName  string
	DeviceDesc  string
	Mac         net.HardwareAddr
}
