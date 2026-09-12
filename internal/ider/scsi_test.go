// SPDX-License-Identifier: Apache-2.0

package ider

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/go-logr/logr"
)

// captureConn is a net.Conn that records everything written and never reads.
type captureConn struct{ writes [][]byte }

func (c *captureConn) Write(p []byte) (int, error) {
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}
func (c *captureConn) Read([]byte) (int, error)         { return 0, nil }
func (c *captureConn) Close() error                     { return nil }
func (c *captureConn) LocalAddr() net.Addr              { return nil }
func (c *captureConn) RemoteAddr() net.Addr             { return nil }
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

// makeISO builds an n-sector image where sector i is filled with byte i.
func makeISO(sectors int) []byte {
	b := make([]byte, sectors*blockSize)
	for i := 0; i < sectors; i++ {
		for j := 0; j < blockSize; j++ {
			b[i*blockSize+j] = byte(i)
		}
	}
	return b
}

func newTestSession(t *testing.T, iso []byte, readBfr int) (*Session, *captureConn) {
	t.Helper()
	cc := &captureConn{}
	s := &Session{
		cfg:     Config{Image: bytes.NewReader(iso), ImageSize: int64(len(iso))},
		log:     logr.Discard(),
		conn:    cc,
		done:    make(chan struct{}),
		readBfr: readBfr,
	}
	return s, cc
}

// data54 extracts the payload of a 0x54 SendDataToHost frame.
// Layout: 8-byte command header + 26-byte data header + payload.
func data54(t *testing.T, frame []byte) []byte {
	t.Helper()
	if len(frame) < 34 || frame[0] != 0x54 {
		t.Fatalf("not a 0x54 data frame: % x", frame)
	}
	return frame[34:]
}

func read10CDB(lba uint32, count uint16) []byte {
	cdb := make([]byte, 12)
	cdb[0] = 0x28
	binary.BigEndian.PutUint32(cdb[2:6], lba)
	binary.BigEndian.PutUint16(cdb[7:9], count)
	return cdb
}

func TestSendDiskData_ChunksAndData(t *testing.T) {
	iso := makeISO(8)
	s, cc := newTestSession(t, iso, 2*blockSize) // 2 sectors per chunk

	if err := s.handleSCSI(devCDDVD, read10CDB(1, 3), 0, 0x10); err != nil {
		t.Fatalf("handleSCSI: %v", err)
	}

	// Expect two 0x54 frames: sectors 1-2, then sector 3.
	var got []byte
	frames := 0
	for _, w := range cc.writes {
		if w[0] == 0x54 {
			frames++
			got = append(got, data54(t, w)...)
		}
	}
	if frames != 2 {
		t.Fatalf("expected 2 data frames, got %d", frames)
	}
	want := iso[1*blockSize : 4*blockSize]
	if !bytes.Equal(got, want) {
		t.Fatalf("returned data mismatch: got %d bytes, want %d", len(got), len(want))
	}

	// Last data frame must carry the completed attribute (byte 3 == 2).
	last := cc.writes[len(cc.writes)-1]
	if last[3] != 2 {
		t.Fatalf("last frame attr = %d, want 2 (completed)", last[3])
	}
	// First data frame must not be completed.
	if cc.writes[0][3] != 0 {
		t.Fatalf("first frame attr = %d, want 0 (not completed)", cc.writes[0][3])
	}
}

func TestSendDiskData_OutOfRange(t *testing.T) {
	s, cc := newTestSession(t, makeISO(4), blockSize)
	if err := s.handleSCSI(devCDDVD, read10CDB(2, 10), 0, 0x10); err != nil {
		t.Fatal(err)
	}
	// A single 0x51 sense frame, no data.
	if len(cc.writes) != 1 || cc.writes[0][0] != 0x51 {
		t.Fatalf("expected one 0x51 sense frame, got % x", cc.writes)
	}
}

func TestReadCapacity(t *testing.T) {
	iso := makeISO(10)
	s, cc := newTestSession(t, iso, blockSize)
	cdb := make([]byte, 12)
	cdb[0] = 0x25
	if err := s.handleSCSI(devCDDVD, cdb, 0, 0x10); err != nil {
		t.Fatal(err)
	}
	if len(cc.writes) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(cc.writes))
	}
	payload := data54(t, cc.writes[0])
	if len(payload) != 8 {
		t.Fatalf("READ_CAPACITY payload = %d bytes, want 8", len(payload))
	}
	lastBlock := binary.BigEndian.Uint32(payload[0:4])
	if lastBlock != uint32(10-1) {
		t.Errorf("last block = %d, want 9", lastBlock)
	}
	blk := binary.BigEndian.Uint32(payload[4:8])
	if blk != blockSize {
		t.Errorf("block size = %d, want %d", blk, blockSize)
	}
}

func TestTestUnitReady_BecomesReady(t *testing.T) {
	s, cc := newTestSession(t, makeISO(2), blockSize)
	cdb := make([]byte, 12) // op 0x00
	// First call: transitions to ready (a check-condition style sense).
	if err := s.handleSCSI(devCDDVD, cdb, 0, 0x10); err != nil {
		t.Fatal(err)
	}
	if !s.cdromReady {
		t.Fatal("cdrom should be marked ready after first TEST_UNIT_READY")
	}
	// Second call: ready.
	if err := s.handleSCSI(devCDDVD, cdb, 0, 0x10); err != nil {
		t.Fatal(err)
	}
	for _, w := range cc.writes {
		if w[0] != 0x51 {
			t.Fatalf("TEST_UNIT_READY should only emit 0x51 sense frames, got % x", w)
		}
	}
}

func TestOpenSessionReplyArmsBoot(t *testing.T) {
	s, cc := newTestSession(t, makeISO(2), 0)
	s.authed = true

	// Craft an OPEN_SESSION reply (0x41): 30 bytes + 0 OEM bytes, seq 0.
	reply := make([]byte, 30)
	reply[0] = 0x41
	binary.LittleEndian.PutUint32(reply[4:8], 0)      // sequence 0 == inSeq
	binary.LittleEndian.PutUint16(reply[16:18], 8192) // read buffer
	binary.LittleEndian.PutUint16(reply[18:20], 8192) // write buffer
	reply[21] = 0                                     // proto 0
	reply[29] = 0                                     // oem len

	established, err := s.feedIDER(reply)
	if err != nil {
		t.Fatalf("feedIDER: %v", err)
	}
	if !established {
		t.Fatal("OPEN_SESSION reply should establish the session")
	}
	// Must have sent a 0x48 enable-features arming IDER on reboot.
	var armed []byte
	for _, w := range cc.writes {
		if w[0] == 0x48 {
			armed = w
		}
	}
	if armed == nil {
		t.Fatal("no 0x48 enable-features frame sent")
	}
	// data = [type][value LE32]; type 3, value 0x09.
	if armed[8] != 3 {
		t.Errorf("enable-features type = %d, want 3", armed[8])
	}
	if v := binary.LittleEndian.Uint32(armed[9:13]); v != iderStartOnReboot {
		t.Errorf("enable-features value = %#x, want %#x", v, iderStartOnReboot)
	}
	if s.readBfr != 8192 {
		t.Errorf("readBfr = %d, want 8192", s.readBfr)
	}
}

func TestKeepAlivePingIsPonged(t *testing.T) {
	s, cc := newTestSession(t, makeISO(1), blockSize)
	s.authed = true
	ping := make([]byte, 8)
	ping[0] = 0x44
	binary.LittleEndian.PutUint32(ping[4:8], 0)
	if _, err := s.feedIDER(ping); err != nil {
		t.Fatal(err)
	}
	if len(cc.writes) != 1 || cc.writes[0][0] != 0x45 {
		t.Fatalf("expected a 0x45 pong, got % x", cc.writes)
	}
}

// cmdEnd returns the last 0x51 command-end frame written.
func lastCmdEnd(t *testing.T, cc *captureConn) []byte {
	t.Helper()
	for i := len(cc.writes) - 1; i >= 0; i-- {
		if len(cc.writes[i]) > 0 && cc.writes[i][0] == 0x51 {
			return cc.writes[i]
		}
	}
	t.Fatal("no 0x51 command-end frame written")
	return nil
}

// TestFloppySlotReportsNoMedium verifies the phantom floppy slot answers every
// media command with a real NOT READY / medium-not-present sense (0x02/0x3a) —
// never a GOOD status (which makes the guest think media is present) and never
// ILLEGAL REQUEST (0x05, which makes Linux usb-storage reset the bus in a loop).
func TestFloppySlotReportsNoMedium(t *testing.T) {
	iso := makeISO(4)
	cmds := map[string][]byte{
		"TEST_UNIT_READY":        {0x00},
		"READ_CAPACITY":          {0x25},
		"READ_FORMAT_CAPACITIES": {0x23},
		"MODE_SENSE_6":           {0x1a, 0x00, 0x3f},
		"MODE_SENSE_10":          {0x5a, 0x00, 0x3f, 0, 0, 0, 0, 0x00, 0xc0},
		"ALLOW_MEDIUM_REMOVAL":   {0x1e},
		"WRITE_10":               {0x2a},
	}
	for name, cdb := range cmds {
		t.Run(name, func(t *testing.T) {
			s, cc := newTestSession(t, iso, blockSize)
			full := make([]byte, 12)
			copy(full, cdb)
			if err := s.handleSCSI(devFloppy, full, 0, devFloppy); err != nil {
				t.Fatalf("handleSCSI: %v", err)
			}
			frame := lastCmdEnd(t, cc)
			if len(frame) < 31 {
				t.Fatalf("short command-end frame: % x", frame)
			}
			marker, sense, asc := frame[20], frame[28], frame[29]
			if marker != 0x87 {
				t.Fatalf("marker = 0x%02x, want CHECK CONDITION 0x87 (not GOOD/other)", marker)
			}
			if sense != 0x02 || asc != 0x3a {
				t.Fatalf("sense = 0x%02x/0x%02x, want 0x02/0x3a (medium not present)", sense, asc)
			}
		})
	}
}
