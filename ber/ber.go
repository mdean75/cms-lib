// Package ber provides a BER to DER normalizer for ASN.1 encoded data.
//
// Go's encoding/asn1 package only accepts Distinguished Encoding Rules (DER),
// a strict canonical subset of Basic Encoding Rules (BER). Real-world CMS
// messages — especially those produced by Windows APIs and older implementations
// — frequently use BER encoding. Normalize converts any valid BER input to
// its canonical DER equivalent.
//
// A key correctness requirement: a zero-length OCTET STRING encoded with
// indefinite length must be preserved as a present-but-empty field after
// normalization. This case arises in CMS SignedData when the content is a
// signed 0-byte payload. Implementations that drop this field incorrectly
// treat the message as a detached signature. See Normalize for details.
package ber

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ASN.1 tag byte structure constants (X.690 section 8.1.2).
const (
	tagClassMask      byte = 0xC0 // bits 7-8: tag class
	tagConstructedBit byte = 0x20 // bit 6: constructed encoding flag
	tagNumMask        byte = 0x1F // bits 1-5: tag number within class
	tagLongFormMarker byte = 0x1F // all tag-number bits set indicates long-form tag
	tagMoreBytesBit   byte = 0x80 // set in long-form tag bytes when more bytes follow
)

// ASN.1 tag class values (X.680 section 8.6).
const (
	classUniversal byte = 0x00
)

// Universal ASN.1 tag numbers (X.680 table 1).
const (
	tagBoolean         byte = 0x01
	tagInteger         byte = 0x02
	tagBitString       byte = 0x03
	tagOctetString     byte = 0x04
	tagUTF8String      byte = 0x0C
	tagNumericString   byte = 0x12
	tagPrintableString byte = 0x13
	tagT61String       byte = 0x14
	tagIA5String       byte = 0x16
	tagUTCTime         byte = 0x17
	tagGeneralizedTime byte = 0x18
	tagVisibleString   byte = 0x1A
	tagGeneralString   byte = 0x1B
)

// Length encoding constants (X.690 section 8.1.3).
const (
	lenIndefinite   byte = 0x80 // length byte value for BER indefinite-length encoding
	lenHighBit      byte = 0x80 // high bit of a length byte; set means long-form
	lenLongFormMask byte = 0x7F // masks the number-of-octets field in a long-form length byte
	lenLongForm1    byte = 0x81 // long-form header: length value in 1 subsequent byte
	lenLongForm2    byte = 0x82 // long-form header: length value in 2 subsequent bytes
	lenLongForm3    byte = 0x83 // long-form header: length value in 3 subsequent bytes
	lenShortFormMax      = 127  // maximum content length encodable in short-form (0–127)
)

// End-of-contents constants (X.690 section 8.1.5).
// An indefinite-length element is terminated by two consecutive eocByte values.
const (
	eocByte byte = 0x00
)

// DER boolean value constants (X.690 section 11.1).
// BER permits any non-zero byte for TRUE; DER requires exactly derBoolTrue.
const (
	derBoolFalse byte = 0x00
	derBoolTrue  byte = 0xFF
)

// intSignBit is the high bit of a byte, used to determine whether a leading
// 0x00 byte is required in a DER INTEGER encoding to prevent sign misinterpretation.
const intSignBit byte = 0x80

// Normalize reads BER-encoded ASN.1 data from r and returns the canonical
// DER encoding. It handles all BER constructs that DER prohibits, including:
//
//   - Indefinite-length encoding (including zero-length content)
//   - Non-minimal length encodings
//   - Constructed encodings of primitive types (bit strings, octet strings, etc.)
//   - Non-canonical boolean values (any non-zero value → 0xFF)
//   - Redundant leading zero bytes in INTEGER encodings
//
// A zero-length value encoded with indefinite length is preserved as a
// zero-length definite-length value. This distinction is critical for CMS
// SignedData: an absent eContent field means detached signature, while a
// present zero-length eContent means a signed 0-byte payload.
func Normalize(r io.Reader) ([]byte, error) {
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("ber: reading input: %w", err)
	}
	var buf bytes.Buffer
	_, err = normalize(input, 0, &buf)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normalize recursively normalizes the BER element starting at input[offset]
// and writes the DER encoding to w. It returns the number of input bytes consumed.
func normalize(input []byte, offset int, w *bytes.Buffer) (int, error) {
	if offset >= len(input) {
		return 0, errors.New("ber: unexpected end of input")
	}

	tagStart := offset
	tagByte, length, headerLen, indefinite, err := readHeader(input, offset)
	if err != nil {
		return 0, err
	}
	offset += headerLen

	isConstructed := tagByte&tagConstructedBit != 0
	tagClass := tagByte & tagClassMask
	tagNum := tagByte & tagNumMask

	// For indefinite-length or constructed primitive types, we must process
	// the content recursively. For definite-length primitive types we may
	// be able to copy or normalize the value bytes directly.
	if indefinite {
		return normalizeIndefinite(input, offset, tagStart, tagByte, tagClass, tagNum, isConstructed, w)
	}

	if offset+length > len(input) {
		return 0, fmt.Errorf("ber: element length %d exceeds available input at offset %d", length, offset)
	}

	content := input[offset : offset+length]
	consumed := headerLen + length

	// Constructed primitive types (e.g., constructed OCTET STRING) must be
	// converted to primitive form per DER rules.
	if isConstructed && isPrimitiveTag(tagClass, tagNum) {
		flat, err := flattenConstructed(content, tagNum)
		if err != nil {
			return 0, err
		}
		writeTag(w, tagByte&^tagConstructedBit, len(flat))
		w.Write(flat)
		return consumed, nil
	}

	// Constructed compound types: recurse into content.
	if isConstructed {
		var inner bytes.Buffer
		pos := 0
		for pos < len(content) {
			n, err := normalize(content, pos, &inner)
			if err != nil {
				return 0, err
			}
			pos += n
		}
		writeTag(w, tagByte, inner.Len())
		w.Write(inner.Bytes())
		return consumed, nil
	}

	// Primitive types: normalize value bytes where necessary.
	normalized, err := normalizePrimitive(tagClass, tagNum, content)
	if err != nil {
		return 0, err
	}
	writeTag(w, tagByte, len(normalized))
	w.Write(normalized)
	return consumed, nil
}

// normalizeIndefinite handles elements encoded with BER indefinite length.
// It reads content elements until the end-of-contents marker (eocByte eocByte),
// normalizes each, and writes a definite-length DER encoding.
func normalizeIndefinite(input []byte, offset, tagStart int, tagByte, tagClass, tagNum byte, isConstructed bool, w *bytes.Buffer) (int, error) {
	var inner bytes.Buffer
	pos := offset

	for {
		if pos+1 >= len(input) {
			return 0, errors.New("ber: missing end-of-contents for indefinite-length element")
		}
		// End-of-contents is two consecutive eocByte values.
		if input[pos] == eocByte && input[pos+1] == eocByte {
			pos += 2
			break
		}
		n, err := normalize(input, pos, &inner)
		if err != nil {
			return 0, err
		}
		pos += n
	}

	consumed := pos - tagStart

	if isConstructed && isPrimitiveTag(tagClass, tagNum) {
		// Flatten constructed primitive (e.g., constructed OCTET STRING).
		flat, err := flattenConstructed(inner.Bytes(), tagNum)
		if err != nil {
			return 0, err
		}
		writeTag(w, tagByte&^tagConstructedBit, len(flat))
		w.Write(flat)
		return consumed, nil
	}

	// Write the normalized content with a definite-length header.
	// For a zero-length indefinite element, inner.Len() == 0. We still write
	// the element with a definite zero length — do NOT omit it. This preserves
	// the distinction between an absent optional field (detached CMS signature)
	// and a present zero-length field (signed 0-byte payload).
	writeTag(w, tagByte, inner.Len())
	w.Write(inner.Bytes())
	return consumed, nil
}

// readHeader parses the tag and length bytes of a BER TLV element starting at
// input[offset]. It returns the tag byte, content length, total header length,
// whether the length is indefinite, and any error.
func readHeader(input []byte, offset int) (tagByte byte, length, headerLen int, indefinite bool, err error) {
	if offset >= len(input) {
		return 0, 0, 0, false, fmt.Errorf("ber: offset %d out of bounds (len %d)", offset, len(input))
	}

	tagByte = input[offset]
	headerLen = 1

	// Long-form tag numbers span multiple bytes; each byte has tagMoreBytesBit
	// set except the last.
	if tagByte&tagNumMask == tagLongFormMarker {
		for {
			if offset+headerLen >= len(input) {
				return 0, 0, 0, false, errors.New("ber: truncated long-form tag")
			}
			b := input[offset+headerLen]
			headerLen++
			if b&tagMoreBytesBit == 0 {
				break
			}
		}
	}

	if offset+headerLen >= len(input) {
		return 0, 0, 0, false, errors.New("ber: truncated length field")
	}

	lenByte := input[offset+headerLen]
	headerLen++

	switch {
	case lenByte == lenIndefinite:
		// Indefinite length: content is terminated by end-of-contents octets.
		indefinite = true
	case lenByte&lenHighBit == 0:
		// Short-form definite length (0–127).
		length = int(lenByte)
	default:
		// Long-form definite length: subsequent bytes encode the length value.
		numBytes := int(lenByte & lenLongFormMask)
		if numBytes == 0 || numBytes > 4 {
			return 0, 0, 0, false, fmt.Errorf("ber: unsupported length field: %d bytes", numBytes)
		}
		if offset+headerLen+numBytes > len(input) {
			return 0, 0, 0, false, errors.New("ber: truncated long-form length")
		}
		var buf [4]byte
		copy(buf[4-numBytes:], input[offset+headerLen:offset+headerLen+numBytes])
		length = int(binary.BigEndian.Uint32(buf[:]))
		headerLen += numBytes
	}

	return tagByte, length, headerLen, indefinite, nil
}

// writeTag writes the DER tag byte and a minimal definite-length encoding for
// the given content length to w.
func writeTag(w *bytes.Buffer, tagByte byte, length int) {
	w.WriteByte(tagByte)
	switch {
	case length <= lenShortFormMax:
		w.WriteByte(byte(length))
	case length < 256:
		w.WriteByte(lenLongForm1)
		w.WriteByte(byte(length))
	case length < 65536:
		w.WriteByte(lenLongForm2)
		w.WriteByte(byte(length >> 8))
		w.WriteByte(byte(length))
	default:
		w.WriteByte(lenLongForm3)
		w.WriteByte(byte(length >> 16))
		w.WriteByte(byte(length >> 8))
		w.WriteByte(byte(length))
	}
}

// isPrimitiveTag reports whether a tag that appears as constructed in BER must
// be primitive in DER. DER requires OCTET STRING, BIT STRING, and all string
// types to use primitive encoding.
func isPrimitiveTag(class, tagNum byte) bool {
	if class != classUniversal {
		// Only Universal-class tags have mandatory primitive/constructed rules in DER.
		return false
	}
	switch tagNum {
	case tagBitString,
		tagOctetString,
		tagUTF8String,
		tagNumericString,
		tagPrintableString,
		tagT61String,
		tagIA5String,
		tagUTCTime,
		tagGeneralizedTime,
		tagVisibleString,
		tagGeneralString:
		return true
	}
	return false
}

// flattenConstructed extracts and concatenates the value bytes from a sequence
// of primitive TLV element chunks. For tagBitString, special handling is required
// for the unused-bits byte per X.690 section 8.6. For all other types the value
// bytes of each chunk are concatenated directly.
func flattenConstructed(content []byte, tagNum byte) ([]byte, error) {
	if tagNum == tagBitString {
		return flattenBitString(content)
	}
	var flat bytes.Buffer
	pos := 0
	for pos < len(content) {
		_, length, headerLen, indefinite, err := readHeader(content, pos)
		if err != nil {
			return nil, fmt.Errorf("ber: flatten: %w", err)
		}
		if indefinite {
			return nil, errors.New("ber: nested indefinite-length in constructed primitive")
		}
		valueStart := pos + headerLen
		valueEnd := valueStart + length
		if valueEnd > len(content) {
			return nil, errors.New("ber: flatten: element length exceeds content")
		}
		flat.Write(content[valueStart:valueEnd])
		pos = valueEnd
	}
	return flat.Bytes(), nil
}

// flattenBitString correctly flattens a sequence of BIT STRING chunks per X.690
// section 8.6. Each chunk begins with an unused-bits byte. Only the final chunk
// may have a non-zero unused-bits byte. The result is the last chunk's unused-bits
// byte followed by the data bytes from all chunks (unused-bits bytes excluded).
func flattenBitString(content []byte) ([]byte, error) {
	var data bytes.Buffer
	var lastUnused byte
	pos := 0
	for pos < len(content) {
		_, length, headerLen, indefinite, err := readHeader(content, pos)
		if err != nil {
			return nil, fmt.Errorf("ber: flatten BIT STRING: %w", err)
		}
		if indefinite {
			return nil, errors.New("ber: nested indefinite-length in constructed BIT STRING")
		}
		valueStart := pos + headerLen
		valueEnd := valueStart + length
		if valueEnd > len(content) {
			return nil, errors.New("ber: flatten BIT STRING: chunk length exceeds content")
		}
		chunk := content[valueStart:valueEnd]
		if len(chunk) == 0 {
			return nil, errors.New("ber: BIT STRING chunk missing unused-bits byte")
		}
		isLast := valueEnd >= len(content)
		unused := chunk[0]
		if !isLast && unused != 0 {
			return nil, errors.New("ber: non-final BIT STRING chunk has non-zero unused bits")
		}
		lastUnused = unused
		data.Write(chunk[1:])
		pos = valueEnd
	}
	result := make([]byte, 1+data.Len())
	result[0] = lastUnused
	copy(result[1:], data.Bytes())
	return result, nil
}

// normalizePrimitive applies DER canonicalization rules to the value bytes of
// a primitive element. Rules applied per tag:
//
//   - tagBoolean: non-zero values are normalized to derBoolTrue (0xFF)
//   - tagInteger: leading zero bytes beyond the minimum needed for sign are removed
//
// All other primitive types are returned as-is; their content is already valid DER
// if the outer encoding (length, construction) has been normalized.
func normalizePrimitive(class, tagNum byte, value []byte) ([]byte, error) {
	if class != classUniversal {
		return value, nil
	}
	switch tagNum {
	case tagBoolean:
		return normalizeBoolean(value)
	case tagInteger:
		return normalizeInteger(value)
	}
	return value, nil
}

// normalizeBoolean normalizes a BER BOOLEAN value to DER. DER requires FALSE to
// be derBoolFalse (0x00) and TRUE to be derBoolTrue (0xFF). BER permits any
// non-zero byte for TRUE.
func normalizeBoolean(value []byte) ([]byte, error) {
	if len(value) != 1 {
		return nil, fmt.Errorf("ber: BOOLEAN value must be 1 byte, got %d", len(value))
	}
	if value[0] == derBoolFalse {
		return value, nil
	}
	return []byte{derBoolTrue}, nil
}

// normalizeInteger normalizes a BER INTEGER value to DER by removing redundant
// leading zero bytes. DER requires the minimum number of bytes to represent the
// value including the sign bit.
func normalizeInteger(value []byte) ([]byte, error) {
	if len(value) == 0 {
		return nil, errors.New("ber: INTEGER value is empty")
	}
	// Remove redundant leading 0x00 bytes, keeping at least one byte and
	// preserving a leading 0x00 required as a sign byte when the next byte
	// has intSignBit set (which would otherwise indicate a negative number).
	i := 0
	for i < len(value)-1 && value[i] == eocByte && value[i+1]&intSignBit == 0 {
		i++
	}
	return value[i:], nil
}
