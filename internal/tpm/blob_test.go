package tpm

import (
	"bytes"
	"testing"
)

func TestBlobRoundTrip(t *testing.T) {
	pub, priv := []byte("public area"), []byte("private area")
	gotPub, gotPriv, err := decodeBlob(encodeBlob(pub, priv))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotPub, pub) || !bytes.Equal(gotPriv, priv) {
		t.Fatalf("decodeBlob = %q, %q; want %q, %q", gotPub, gotPriv, pub, priv)
	}
}

// A corrupt or truncated blob must fail cleanly, never panic, since it is
// read from disk before the TPM ever sees it.
func TestDecodeBlobRejectsTruncation(t *testing.T) {
	valid := encodeBlob([]byte("pub"), []byte("priv"))
	tests := []struct {
		name string
		blob []byte
	}{
		{"empty", nil},
		{"shorter than both lengths", valid[:7]},
		{"public area cut", valid[:5]},
		{"private length missing", valid[:4+3+2]},
		{"private area cut", valid[:len(valid)-1]},
		{"huge public length", []byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}},
		{"huge private length", []byte{0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := decodeBlob(tt.blob); err == nil {
				t.Fatal("decodeBlob accepted a truncated blob")
			}
		})
	}
}
