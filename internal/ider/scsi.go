// SPDX-License-Identifier: Apache-2.0

package ider

import (
	"encoding/binary"
	"fmt"
)

// IDER device ids on the redirection wire.
const (
	devFloppy = 0xA0
	devCDDVD  = 0xB0
)

// iderStartOnReboot enables the IDER register and arms it for the next host
// reboot (0x01 enable | 0x08 on-reboot), matching MeshCentral's "OnReboot".
const iderStartOnReboot = 0x01 | 0x08

// startIDER sends OPEN_SESSION to begin the IDER command stream.
func (s *Session) startIDER() error {
	s.outSeq = 0
	s.inSeq = 0
	s.iderAcc = nil
	s.cdromReady = false

	// OPEN_SESSION: rx_timeout, tx_timeout, heartbeat (LE16), version (LE32).
	data := make([]byte, 0, 10)
	data = appendLE16(data, 30000) // rx timeout
	data = appendLE16(data, 0)     // tx timeout
	data = appendLE16(data, 20000) // heartbeat
	data = appendLE32(data, 1)     // version
	return s.sendCommand(0x40, data, false, false)
}

// feedIDER appends incoming bytes and processes as many complete IDER
// commands as are buffered. It returns established=true once the
// OPEN_SESSION reply has been handled.
func (s *Session) feedIDER(data []byte) (established bool, err error) {
	s.iderAcc = append(s.iderAcc, data...)
	for len(s.iderAcc) > 0 {
		consumed, estd, err := s.processIDER()
		if err != nil {
			return established, err
		}
		if consumed == 0 {
			break // need more bytes
		}
		if len(s.iderAcc) < 4 {
			return established, fmt.Errorf("ider: short frame")
		}
		if seq := binary.LittleEndian.Uint32(s.iderAcc[4:8]); seq != s.inSeq {
			return established, fmt.Errorf("ider: out of sequence: got %d want %d", seq, s.inSeq)
		}
		s.inSeq++
		s.iderAcc = s.iderAcc[consumed:]
		if estd {
			established = true
		}
	}
	return established, nil
}

// processIDER handles the command at the head of iderAcc. It returns the
// number of bytes consumed (0 if incomplete).
func (s *Session) processIDER() (consumed int, established bool, err error) {
	acc := s.iderAcc
	if len(acc) < 8 {
		return 0, false, nil
	}
	switch acc[0] {
	case 0x41: // OPEN_SESSION reply
		if len(acc) < 30 {
			return 0, false, nil
		}
		oemLen := int(acc[29])
		if len(acc) < 30+oemLen {
			return 0, false, nil
		}
		s.readBfr = int(binary.LittleEndian.Uint16(acc[16:18]))
		writeBfr := int(binary.LittleEndian.Uint16(acc[18:20]))
		proto := acc[21]
		if proto != 0 {
			return 0, false, fmt.Errorf("ider: unsupported redirection proto %d", proto)
		}
		if s.readBfr <= 0 || s.readBfr > 8192 {
			return 0, false, fmt.Errorf("ider: illegal read buffer size %d", s.readBfr)
		}
		if writeBfr > 8192 {
			return 0, false, fmt.Errorf("ider: illegal write buffer size %d", writeBfr)
		}
		s.dbg("OPEN_SESSION reply: readbfr=%d writebfr=%d proto=%d", s.readBfr, writeBfr, proto)
		// Arm IDER for the next reboot.
		if err := s.sendEnableFeatures(3, iderStartOnReboot); err != nil {
			return 0, false, err
		}
		return 30 + oemLen, true, nil

	case 0x43: // CLOSE
		return 0, false, fmt.Errorf("ider: device closed the session")

	case 0x44: // KEEPALIVE PING
		if err := s.sendCommand(0x45, nil, false, false); err != nil {
			return 0, false, err
		}
		return 8, false, nil

	case 0x45: // KEEPALIVE PONG
		return 8, false, nil

	case 0x46: // RESET OCCURRED
		if len(acc) < 9 {
			return 0, false, nil
		}
		// No async read is in flight (reads are synchronous here), so ack now.
		if err := s.sendCommand(0x47, nil, false, false); err != nil {
			return 0, false, err
		}
		return 9, false, nil

	case 0x49: // STATUS_DATA (enable/disable features reply)
		if len(acc) < 13 {
			return 0, false, nil
		}
		return 13, false, nil

	case 0x4A: // ERROR OCCURRED
		if len(acc) < 11 {
			return 0, false, nil
		}
		s.log.V(1).Info("ider: device reported error", "code", acc[8])
		return 11, false, nil

	case 0x4B: // HEARTBEAT
		return 8, false, nil

	case 0x50: // COMMAND WRITTEN (SCSI CDB)
		if len(acc) < 28 {
			return 0, false, nil
		}
		device := byte(devFloppy)
		if acc[14]&0x10 != 0 {
			device = devCDDVD
		}
		deviceFlags := acc[14]
		featureRegister := acc[9]
		cdb := append([]byte(nil), acc[16:28]...)
		if err := s.handleSCSI(device, cdb, featureRegister, deviceFlags); err != nil {
			return 0, false, err
		}
		return 28, false, nil

	case 0x53: // DATA FROM HOST (write) - unsupported, report no medium
		if len(acc) < 14 {
			return 0, false, nil
		}
		dataLen := int(binary.LittleEndian.Uint16(acc[9:11]))
		if len(acc) < 14+dataLen {
			return 0, false, nil
		}
		// Fixed "write protected / no medium" completion, per reference.
		resp := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87, 0x70, 0x03, 0, 0, 0, 0xa0, 0x51, 0x07, 0x27, 0x00}
		if err := s.sendCommand(0x51, resp, true, false); err != nil {
			return 0, false, err
		}
		return 14 + dataLen, false, nil

	default:
		return 0, false, fmt.Errorf("ider: unknown command 0x%02x", acc[0])
	}
}

// sendCommand frames and writes an IDER command.
func (s *Session) sendCommand(cmdID byte, data []byte, completed, dma bool) error {
	var attr byte
	if cmdID > 50 && completed {
		attr = 2
	}
	if dma {
		attr++
	}
	frame := make([]byte, 0, 8+len(data))
	frame = append(frame, cmdID, 0, 0, attr)
	frame = appendLE32(frame, s.outSeq)
	s.outSeq++
	frame = append(frame, data...)
	return s.send(frame)
}

// sendEnableFeatures sends a DisableEnableFeatures (0x48) command.
func (s *Session) sendEnableFeatures(typ byte, value uint32) error {
	data := append([]byte{typ}, le32(value)...)
	return s.sendCommand(0x48, data, false, false)
}

// sendCommandEndResponse sends a SCSI completion/sense (0x51).
func (s *Session) sendCommandEndResponse(genericStatus bool, sense, device, asc, asq byte) error {
	if !genericStatus {
		s.dbg("SENSE dev=0x%02x sense=0x%02x asc=0x%02x asq=0x%02x", device, sense, asc, asq)
	}
	var resp []byte
	if genericStatus {
		resp = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xc5, 0, 3, 0, 0, 0, device, 0x50, 0, 0, 0}
	} else {
		resp = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x87, sense << 4, 3, 0, 0, 0, device, 0x51, sense, asc, asq}
	}
	return s.sendCommand(0x51, resp, true, false)
}

// sendDataToHost sends read data (0x54).
func (s *Session) sendDataToHost(device byte, completed bool, data []byte, dma bool) error {
	dmaLen := len(data)
	if dma {
		dmaLen = 0
	}
	dl := len(data)
	var b5 byte = 0xb5
	if dma {
		b5 = 0xb4
	}
	var hdr []byte
	if completed {
		hdr = []byte{0, byte(dl & 0xff), byte(dl >> 8), 0, b5, 0, 2, 0, byte(dmaLen & 0xff), byte(dmaLen >> 8), device, 0x58, 0x85, 0, 3, 0, 0, 0, device, 0x50, 0, 0, 0, 0, 0, 0}
	} else {
		hdr = []byte{0, byte(dl & 0xff), byte(dl >> 8), 0, b5, 0, 2, 0, byte(dmaLen & 0xff), byte(dmaLen >> 8), device, 0x58, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	}
	return s.sendCommand(0x54, append(hdr, data...), completed, dma)
}

// handleSCSI dispatches an ATAPI command from the host.
func (s *Session) handleSCSI(dev byte, cdb []byte, featureRegister, deviceFlags byte) error {
	dma := featureRegister&1 != 0
	s.dbg("SCSI op=0x%02x dev=0x%02x fr=0x%02x dma=%v cdb=% x", cdb[0], dev, featureRegister, dma, cdb)
	switch cdb[0] {
	case 0x00: // TEST_UNIT_READY
		if dev == devCDDVD {
			if !s.cdromReady {
				s.cdromReady = true
				return s.sendCommandEndResponse(true, 0x06, dev, 0x28, 0x00)
			}
			return s.sendCommandEndResponse(true, 0x00, dev, 0x00, 0x00)
		}
		// Floppy slot: report NOT READY / medium not present as a real sense.
		// A GOOD status here makes Linux believe an empty floppy has media and
		// then hammer MODE_SENSE/READ_CAPACITY, resetting the USB bus in a loop.
		return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00)

	case 0x08: // READ_6
		lba := (int64(cdb[1]&0x1f) << 16) | (int64(cdb[2]) << 8) | int64(cdb[3])
		n := int64(cdb[4])
		if n == 0 {
			n = 256
		}
		return s.sendDiskData(dev, lba, n, dma)

	case 0x28: // READ_10
		lba := int64(binary.BigEndian.Uint32(cdb[2:6]))
		n := int64(binary.BigEndian.Uint16(cdb[7:9]))
		return s.sendDiskData(dev, lba, n, dma)

	case 0x0a, 0x2a, 0x2e: // WRITE_6 / WRITE_10 / WRITE_AND_VERIFY - not supported
		return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00)

	case 0x1a: // MODE_SENSE_6
		if dev != devCDDVD {
			return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00) // floppy: no medium present
		}
		if cdb[2] == 0x3f && cdb[3] == 0x00 {
			return s.sendDataToHost(dev, true, []byte{0, 0x05, 0x80, 0}, dma)
		}
		return s.sendCommandEndResponse(false, 0x05, dev, 0x24, 0x00)

	case 0x1b: // START_STOP
		return s.sendCommandEndResponse(true, 0, dev, 0, 0)

	case 0x1e: // ALLOW_MEDIUM_REMOVAL
		if dev == devCDDVD {
			return s.sendCommandEndResponse(true, 0x00, dev, 0x00, 0x00)
		}
		return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00)

	case 0x23: // READ_FORMAT_CAPACITIES
		if dev != devCDDVD {
			return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00) // floppy: no medium present
		}
		payload := append(be32(8), []byte{0x00, 0x00, 0x0b, 0x40, 0x02, 0x00, 0x02, 0x00}...)
		return s.sendDataToHost(dev, true, payload, dma)

	case 0x25: // READ_CAPACITY
		if dev != devCDDVD || s.cfg.ImageSize == 0 {
			return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00)
		}
		lastBlock := uint32(s.cfg.ImageSize>>11) - 1
		payload := append(be32(lastBlock), []byte{0, 0, 0x08, 0}...) // 0x0800 = 2048-byte blocks
		return s.sendDataToHost(deviceFlags, true, payload, dma)

	case 0x43: // READ_TOC
		if dev != devCDDVD {
			return s.sendCommandEndResponse(true, 0x05, dev, 0x20, 0x00)
		}
		msf := cdb[1]&0x02 != 0
		format := cdb[2] & 0x07
		if format == 0 {
			format = cdb[9] >> 6
		}
		switch {
		case format == 1:
			return s.sendDataToHost(dev, true, []byte{0x00, 0x0a, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}, dma)
		case msf:
			return s.sendDataToHost(dev, true, []byte{0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x14, 0xaa, 0x00, 0x00, 0x00, 0x34, 0x13}, dma)
		default:
			return s.sendDataToHost(dev, true, []byte{0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00}, dma)
		}

	case 0x46: // GET_CONFIGURATION
		return s.getConfiguration(dev, cdb, dma)

	case 0x4a: // GET_EVENT_STATUS_NOTIFICATION
		if cdb[1] != 0x01 && cdb[4] != 0x10 {
			return s.sendCommandEndResponse(true, 0x05, dev, 0x26, 0x01)
		}
		present := byte(0x00)
		if dev == devCDDVD && s.cfg.ImageSize > 0 {
			present = 0x02
		}
		return s.sendDataToHost(dev, true, []byte{0x00, present, 0x80, 0x00}, dma)

	case 0x4c:
		resp := append(append(append(be32(0), be32(0)...), be32(0)...), []byte{0x87, 0x50, 0x03, 0x00, 0x00, 0x00, 0xb0, 0x51, 0x05, 0x20, 0x00}...)
		return s.sendCommand(0x51, resp, true, false)

	case 0x51: // READ_DISC_INFO
		return s.sendCommandEndResponse(false, 0x05, dev, 0x20, 0x00)

	case 0x55: // MODE_SELECT_10
		return s.sendCommandEndResponse(true, 0x05, dev, 0x20, 0x00)

	case 0x5a: // MODE_SENSE_10
		return s.modeSense10(dev, cdb, dma)

	case 0xac: // GET_PERFORMANCE
		return s.sendDataToHost(dev, true, []byte{0x00, 0x00, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00}, dma)

	default:
		s.log.V(1).Info("ider: unhandled SCSI command", "op", fmt.Sprintf("0x%02x", cdb[0]))
		return s.sendCommandEndResponse(false, 0x05, dev, 0x20, 0x00)
	}
}

// getConfiguration answers 0x46 GET_CONFIGURATION with the CD feature list.
func (s *Session) getConfiguration(dev byte, cdb []byte, dma bool) error {
	sendAll := cdb[1] != 2
	firstCode := int(binary.BigEndian.Uint16(cdb[2:4]))
	bufLen := int(binary.BigEndian.Uint16(cdb[7:9]))

	if bufLen == 0 {
		return s.sendDataToHost(dev, true, append(be32(0x003c), be32(0x0008)...), dma)
	}

	var feature []byte
	pick := func(code int, arr []byte) {
		if feature == nil && (firstCode == code || (sendAll && firstCode < code)) {
			feature = arr
		}
	}
	pick(0x0, []byte{0x00, 0x00, 0x03, 0x04, 0x00, 0x08, 0x01, 0x00})                          // Profile List
	pick(0x1, []byte{0x00, 0x01, 0x03, 0x04, 0x00, 0x00, 0x00, 0x02})                          // Core
	pick(0x2, []byte{0x00, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00})                          // Morphing
	pick(0x3, []byte{0x00, 0x03, 0x03, 0x04, 0x29, 0x00, 0x00, 0x02})                          // Removable
	pick(0x10, []byte{0x00, 0x10, 0x01, 0x08, 0x00, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00, 0x00}) // Random Readable
	pick(0x1e, []byte{0x00, 0x1E, 0x03, 0x00})                                                 // Read
	pick(0x100, []byte{0x01, 0x00, 0x03, 0x00})                                                // Power Management
	pick(0x105, []byte{0x01, 0x05, 0x03, 0x00})                                                // Timeout

	var r []byte
	if feature == nil {
		r = append(be32(0x0008), be32(4)...)
	} else {
		r = append(append(be32(0x0008), be32(uint32(len(feature)+4))...), feature...)
	}
	if len(r) > bufLen {
		r = r[:bufLen]
	}
	return s.sendDataToHost(dev, true, r, dma)
}

// modeSense10 answers 0x5a MODE_SENSE_10 with CD mode pages.
func (s *Session) modeSense10(dev byte, cdb []byte, dma bool) error {
	bufLen := int(binary.BigEndian.Uint16(cdb[7:9]))
	if bufLen == 0 {
		return s.sendDataToHost(dev, true, append(be32(0x003c), be32(0x0008)...), dma)
	}
	if dev != devCDDVD {
		return s.sendCommandEndResponse(false, 0x02, dev, 0x3a, 0x00) // floppy: no medium present
	}
	var r []byte
	switch cdb[2] & 0x3f {
	case 0x01:
		r = []byte{0x00, 0x0E, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00}
	case 0x1A:
		r = []byte{0x00, 0x12, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 0x1D:
		r = []byte{0x00, 0x12, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x1D, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 0x2A:
		r = []byte{0x00, 0x20, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x18, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 0x3f:
		r = []byte{0x00, 0x28, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x06, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x18, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	if r == nil {
		return s.sendCommandEndResponse(false, 0x05, dev, 0x20, 0x00)
	}
	return s.sendDataToHost(dev, true, r, dma)
}

// sendDiskData reads the requested LBA range from the image and streams it to
// the host in chunks bounded by the device's read buffer.
func (s *Session) sendDiskData(dev byte, lba, count int64, dma bool) error {
	if dev != devCDDVD {
		return s.sendCommandEndResponse(true, 0x02, dev, 0x3a, 0x00)
	}
	mediaBlocks := s.cfg.ImageSize >> 11
	if count < 0 || lba+count > mediaBlocks {
		return s.sendCommandEndResponse(false, 0x05, dev, 0x21, 0x00) // LBA out of range
	}
	if count == 0 {
		return s.sendCommandEndResponse(true, 0x00, dev, 0x00, 0x00)
	}
	s.dbg("READ dev=0x%02x lba=%d count=%d", dev, lba, count)
	offset := lba << 11
	remaining := count << 11
	maxChunk := int64(s.readBfr)
	if maxChunk <= 0 {
		maxChunk = 8192
	}
	for remaining > 0 {
		chunk := remaining
		if chunk > maxChunk {
			chunk = maxChunk
		}
		buf := make([]byte, chunk)
		if _, err := s.cfg.Image.ReadAt(buf, offset); err != nil {
			return fmt.Errorf("ider: reading image at %d: %w", offset, err)
		}
		offset += chunk
		remaining -= chunk
		if err := s.sendDataToHost(dev, remaining == 0, buf, dma); err != nil {
			return err
		}
	}
	return nil
}

// --- little/big endian helpers ---

func appendLE16(dst []byte, v uint16) []byte {
	var b [2]byte
	binary.LittleEndian.PutUint16(b[:], v)
	return append(dst, b[:]...)
}

func le32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

func be32(v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return b[:]
}
