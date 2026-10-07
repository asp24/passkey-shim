package kernel

import (
	"bytes"
	"testing"

	"llavero/internal/hidbridge"
	"llavero/internal/uhid"
)

func TestTranslate(t *testing.T) {
	report := bytes.Repeat([]byte{0x5a}, hidbridge.ReportSize)
	tests := []struct {
		name   string
		in     uhid.Event
		want   hidbridge.Event
		wantOK bool
	}{
		{"start", uhid.Event{Kind: uhid.EventStart}, hidbridge.Event{Kind: hidbridge.EventStart}, true},
		{"stop", uhid.Event{Kind: uhid.EventStop}, hidbridge.Event{Kind: hidbridge.EventStop}, true},
		{"open", uhid.Event{Kind: uhid.EventOpen}, hidbridge.Event{Kind: hidbridge.EventOpen}, true},
		{"close", uhid.Event{Kind: uhid.EventClose}, hidbridge.Event{Kind: hidbridge.EventClose}, true},
		{"output", uhid.Event{Kind: uhid.EventOutput, Data: report}, hidbridge.Event{Kind: hidbridge.EventOutput, Data: report}, true},
		{"get report request", uhid.Event{Kind: 9}, hidbridge.Event{}, false},
		{"set report request", uhid.Event{Kind: 13}, hidbridge.Event{}, false},
		{"destroy is not forwarded", uhid.Event{Kind: 1}, hidbridge.Event{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := translate(tt.in)
			if ok != tt.wantOK || got.Kind != tt.want.Kind || !bytes.Equal(got.Data, tt.want.Data) {
				t.Fatalf("translate(%+v) = %+v, %v; want %+v, %v", tt.in, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
