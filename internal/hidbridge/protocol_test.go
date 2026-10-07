package hidbridge

import (
	"bytes"
	"testing"
)

func TestEncodeEvent(t *testing.T) {
	report := bytes.Repeat([]byte{0xab}, ReportSize)
	tests := []struct {
		name    string
		ev      Event
		want    []byte
		wantErr bool
	}{
		{"start", Event{Kind: EventStart}, []byte{EventStart}, false},
		{"close", Event{Kind: EventClose}, []byte{EventClose}, false},
		{"output", Event{Kind: EventOutput, Data: report}, append([]byte{EventOutput}, report...), false},
		{"lifecycle with data", Event{Kind: EventOpen, Data: []byte{1}}, nil, true},
		{"short output", Event{Kind: EventOutput, Data: report[:63]}, nil, true},
		{"long output", Event{Kind: EventOutput, Data: append(report, 0)}, nil, true},
		{"control byte as event", Event{Kind: Ready}, nil, true},
		{"unknown kind", Event{Kind: 11}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := encodeEvent(tt.ev)
			if (err != nil) != tt.wantErr {
				t.Fatalf("encodeEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("encodeEvent() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestDecodeEvent(t *testing.T) {
	report := bytes.Repeat([]byte{0xcd}, ReportSize)
	tests := []struct {
		name    string
		packet  []byte
		want    Event
		wantErr bool
	}{
		{"stop", []byte{EventStop}, Event{Kind: EventStop}, false},
		{"output", append([]byte{EventOutput}, report...), Event{Kind: EventOutput, Data: report}, false},
		{"empty", nil, Event{}, true},
		{"lifecycle with data", []byte{EventStart, 0}, Event{}, true},
		{"bare output", []byte{EventOutput}, Event{}, true},
		{"truncated output", append([]byte{EventOutput}, report[:10]...), Event{}, true},
		{"oversized output", append(append([]byte{EventOutput}, report...), 0), Event{}, true},
		{"unknown kind", []byte{0xff}, Event{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeEvent(tt.packet)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decodeEvent() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got.Kind != tt.want.Kind || !bytes.Equal(got.Data, tt.want.Data) {
				t.Fatalf("decodeEvent() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
