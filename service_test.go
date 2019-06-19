package librjsocks

import (
	"fmt"
	"testing"
)

func TestService(t *testing.T) {
	// devName := flag.String("dev", "", "network device")
	infos, err := FindAllAdapters()
	if err != nil {
		t.Fatal(err)
	}
	for _, info := range infos {
		fmt.Printf("%s\n", info.AdapterName)
		if info.AdapterName == "eth0" {
			fmt.Printf("%+v\n", info)
			service, err := NewService("username", "password", &info)
			if err != nil {
				t.Fatal(err)
			}
			service.Run()
			break
		}
	}
}
