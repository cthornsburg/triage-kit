package collect

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"
)

func TestParseUSBStorDiskID(t *testing.T) {
	parts := parseUSBStorDiskID("Disk&Ven_SanDisk&Prod_Ultra_Fit&Rev_1.00")
	if parts.Vendor != "SanDisk" {
		t.Fatalf("vendor = %q", parts.Vendor)
	}
	if parts.Product != "Ultra Fit" {
		t.Fatalf("product = %q", parts.Product)
	}
	if parts.Revision != "1.00" {
		t.Fatalf("revision = %q", parts.Revision)
	}
}

func TestSerialCandidateFromDeviceID(t *testing.T) {
	got := serialCandidateFromDeviceID(`USBSTOR\Disk&Ven_SanDisk&Prod_Ultra\4C530001230101114432&0`)
	if got != "4C530001230101114432&0" {
		t.Fatalf("serial candidate = %q", got)
	}
}

func TestDecodeMountedDeviceValueUTF16(t *testing.T) {
	text := `\??\USBSTOR#Disk&Ven_SanDisk&Prod_Ultra#4C530001230101114432&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`
	encoded := utf16.Encode([]rune(text))
	data := make([]byte, len(encoded)*2)
	for i, unit := range encoded {
		binary.LittleEndian.PutUint16(data[i*2:], unit)
	}
	if got := decodeMountedDeviceValue(data); got != text {
		t.Fatalf("decoded mounted-device value = %q", got)
	}
}
