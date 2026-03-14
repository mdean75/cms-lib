// Package ber provides a BER to DER normalizer for ASN.1 encoded data.
//
// Go's encoding/asn1 package only accepts Distinguished Encoding Rules (DER),
// a strict canonical subset of Basic Encoding Rules (BER). Real-world CMS
// messages — especially those produced by Windows APIs and older implementations
// — frequently use BER encoding. ToDER converts any valid BER input to
// its canonical DER equivalent.
//
// A key correctness requirement: a zero-length OCTET STRING encoded with
// indefinite length must be preserved as a present-but-empty field after
// normalization. This case arises in CMS SignedData when the content is a
// signed 0-byte payload. Implementations that drop this field incorrectly
// treat the message as a detached signature. See ToDER for details.
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
	lenLongForm1Octet  byte = 0x81 // long-form header: length value in 1 subsequent octet
	lenLongForm2Octets byte = 0x82 // long-form header: length value in 2 subsequent octets
	lenLongForm3Octets byte = 0x83 // long-form header: length value in 3 subsequent octets
	lenLongForm4Octets byte = 0x84 // long-form header: length value in 4 subsequent octets
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

// headerInfo holds the parsed fields of a BER TLV header returned by readHeader.
type headerInfo struct {
	tagByte     byte // first byte of the tag field
	length      int  // content length (0 when indefinite)
	headerLen   int  // total bytes consumed by tag + length fields
	numTagBytes int  // bytes used by the tag field alone (1 for short-form, ≥2 for long-form)
	indefinite  bool // true when the length is BER indefinite (0x80)
}

// Static sentinel errors for the ber package. Dynamic errors (those that include
// offset or length context) are constructed with fmt.Errorf wrapping these sentinels
// so callers can use errors.Is for category matching.
var (
	errUnexpectedEOI               = errors.New("ber: unexpected end of input")
	errMissingEOC                  = errors.New("ber: missing end-of-contents for indefinite-length element")
	errTruncatedLongFormTag        = errors.New("ber: truncated long-form tag")
	errTruncatedLengthField        = errors.New("ber: truncated length field")
	errTruncatedLongFormLength     = errors.New("ber: truncated long-form length")
	errNestedIndefinitePrimitive   = errors.New("ber: nested indefinite-length in constructed primitive")
	errFlattenLengthExceeds        = errors.New("ber: flatten: element length exceeds content")
	errNestedIndefiniteBitString   = errors.New("ber: nested indefinite-length in constructed BIT STRING")
	errFlattenBitStringExceeds     = errors.New("ber: flatten BIT STRING: chunk length exceeds content")
	errBitStringMissingUnusedBits  = errors.New("ber: BIT STRING chunk missing unused-bits byte")
	errNonFinalBitStringUnusedBits = errors.New("ber: non-final BIT STRING chunk has non-zero unused bits")
	errIntegerEmpty                = errors.New("ber: INTEGER value is empty")
	// base sentinels wrapped with dynamic context by callers:
	errElementLengthExceeds   = errors.New("ber: element length exceeds available input")
	errOffsetOutOfBounds      = errors.New("ber: offset out of bounds")
	errUnsupportedLengthField = errors.New("ber: unsupported length field")
	errBooleanLength          = errors.New("ber: BOOLEAN value must be 1 byte")
)

// ToDER reads BER-encoded ASN.1 data from r and returns the canonical
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
func ToDER(r io.Reader) ([]byte, error) {
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
		return 0, errUnexpectedEOI
	}

	tagStart := offset
	hdr, err := readHeader(input, offset)
	if err != nil {
		return 0, err
	}
	offset += hdr.headerLen

	isConstructed := hdr.tagByte&tagConstructedBit != 0
	tagClass := hdr.tagByte & tagClassMask
	tagNum := hdr.tagByte & tagNumMask

	// tagBytes holds all bytes of the tag field. For short-form tags this is
	// one byte; for long-form tags (tag number ≥ 31) it is two or more bytes.
	// We must emit all tag bytes verbatim to preserve long-form tag numbers.
	tagBytes := input[tagStart : tagStart+hdr.numTagBytes]

	// For indefinite-length or constructed primitive types, we must process
	// the content recursively. For definite-length primitive types we may
	// be able to copy or normalize the value bytes directly.
	if hdr.indefinite {
		return normalizeIndefinite(
			input, offset, tagStart, hdr.tagByte, tagClass, tagNum, isConstructed, hdr.numTagBytes, w,
		)
	}

	if offset+hdr.length > len(input) {
		return 0, fmt.Errorf("ber: element length %d at offset %d: %w",
			hdr.length, offset, errElementLengthExceeds)
	}

	content := input[offset : offset+hdr.length]
	consumed := hdr.headerLen + hdr.length

	// Constructed primitive types (e.g., constructed OCTET STRING) must be
	// converted to primitive form per DER rules. Clear the constructed bit in
	// the first tag byte while preserving any remaining long-form tag bytes.
	if isConstructed && isPrimitiveTag(tagClass, tagNum) {
		return consumed, normalizeConstructedPrimitive(tagBytes, content, tagNum, w)
	}

	// Constructed compound types: recurse into content.
	if isConstructed {
		return consumed, normalizeConstructedCompound(tagBytes, content, w)
	}

	// Primitive types: normalize value bytes where necessary.
	normalized, err := normalizePrimitive(tagClass, tagNum, content)
	if err != nil {
		return 0, err
	}
	writeTLV(w, tagBytes, len(normalized))
	w.Write(normalized)
	return consumed, nil
}

// normalizeConstructedPrimitive flattens a constructed primitive type (e.g.
// constructed OCTET STRING or BIT STRING) to its DER primitive form. The
// constructed bit is cleared from tagBytes[0] and the flattened content is
// written with a new definite-length header.
func normalizeConstructedPrimitive(tagBytes, content []byte, tagNum byte, w *bytes.Buffer) error {
	flat, err := flattenConstructed(content, tagNum)
	if err != nil {
		return err
	}
	primTag := append([]byte(nil), tagBytes...)
	primTag[0] &^= tagConstructedBit
	writeTLV(w, primTag, len(flat))
	w.Write(flat)
	return nil
}

// normalizeConstructedCompound recursively normalizes each child element of a
// constructed compound type (e.g. SEQUENCE or SET) and writes the outer
// definite-length TLV wrapper.
func normalizeConstructedCompound(tagBytes, content []byte, w *bytes.Buffer) error {
	var inner bytes.Buffer
	pos := 0
	for pos < len(content) {
		n, err := normalize(content, pos, &inner)
		if err != nil {
			return err
		}
		pos += n
	}
	writeTLV(w, tagBytes, inner.Len())
	w.Write(inner.Bytes())
	return nil
}

// normalizeIndefinite handles elements encoded with BER indefinite length.
// It reads content elements until the end-of-contents marker (eocByte eocByte),
// normalizes each, and writes a definite-length DER encoding.
// numTagBytes is the number of bytes the tag field occupies in input starting
// at tagStart; it is used to slice the full tag bytes for re-emission.
func normalizeIndefinite(
	input []byte, offset, tagStart int,
	tagByte, tagClass, tagNum byte,
	isConstructed bool, numTagBytes int,
	w *bytes.Buffer,
) (int, error) {
	tagBytes := input[tagStart : tagStart+numTagBytes]

	var inner bytes.Buffer
	pos := offset

	for {
		if pos+1 >= len(input) {
			return 0, errMissingEOC
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
		primTag := append([]byte(nil), tagBytes...)
		primTag[0] &^= tagConstructedBit
		writeTLV(w, primTag, len(flat))
		w.Write(flat)
		return consumed, nil
	}

	// For non-constructed (primitive) types with indefinite-length encoding,
	// apply the same content normalization as for definite-length primitives.
	// This rejects malformed content (e.g., a BOOLEAN with zero content bytes)
	// rather than silently emitting DER that fails a subsequent normalization.
	// For a zero-length indefinite element, inner.Len() == 0. We still write
	// the element with a definite zero length — do NOT omit it. This preserves
	// the distinction between an absent optional field (detached CMS signature)
	// and a present zero-length field (signed 0-byte payload).
	if !isConstructed {
		normalized, err := normalizePrimitive(tagClass, tagNum, inner.Bytes())
		if err != nil {
			return 0, err
		}
		writeTLV(w, tagBytes, len(normalized))
		w.Write(normalized)
		return consumed, nil
	}

	writeTLV(w, tagBytes, inner.Len())
	w.Write(inner.Bytes())
	return consumed, nil
}

// readHeader parses the tag and length bytes of a BER TLV element starting at
// input[offset] and returns the parsed fields as a headerInfo. The tagByte field
// is the first byte of the tag; headerLen is the total bytes consumed by the tag
// and length fields together; numTagBytes is the bytes used by the tag field alone
// (1 for short-form, ≥2 for long-form tags with number ≥ 31).
//
// Callers that need to re-emit the tag verbatim should use
// input[offset : offset+hdr.numTagBytes] rather than hdr.tagByte alone.
func readHeader(input []byte, offset int) (headerInfo, error) {
	if offset >= len(input) {
		return headerInfo{}, fmt.Errorf("ber: offset %d out of bounds (len %d): %w",
			offset, len(input), errOffsetOutOfBounds)
	}

	hdr := headerInfo{
		tagByte:     input[offset],
		headerLen:   1,
		numTagBytes: 1,
	}

	// Long-form tag numbers span multiple bytes; each byte has tagMoreBytesBit
	// set except the last.
	if hdr.tagByte&tagNumMask == tagLongFormMarker {
		for {
			if offset+hdr.headerLen >= len(input) {
				return headerInfo{}, errTruncatedLongFormTag
			}
			b := input[offset+hdr.headerLen]
			hdr.headerLen++
			hdr.numTagBytes++
			if b&tagMoreBytesBit == 0 {
				break
			}
		}
	}

	if offset+hdr.headerLen >= len(input) {
		return headerInfo{}, errTruncatedLengthField
	}

	lenByte := input[offset+hdr.headerLen]
	hdr.headerLen++

	switch {
	case lenByte == lenIndefinite:
		// Indefinite length: content is terminated by end-of-contents octets.
		hdr.indefinite = true
	case lenByte&lenHighBit == 0:
		// Short-form definite length (0–127).
		hdr.length = int(lenByte)
	default:
		// Long-form definite length: subsequent bytes encode the length value.
		numBytes := int(lenByte & lenLongFormMask)
		var err error
		hdr.length, hdr.headerLen, err = readLongFormLength(input, offset, hdr.headerLen, numBytes)
		if err != nil {
			return headerInfo{}, err
		}
	}

	return hdr, nil
}

// readLongFormLength decodes a BER long-form definite length. numBytes is the
// count extracted from the high-byte mask of the length field. It returns the
// decoded length, the updated headerLen (advanced past the length bytes), and
// any error. offset and headerLen together identify where the length bytes begin.
func readLongFormLength(input []byte, offset, headerLen, numBytes int) (length, newHeaderLen int, err error) {
	if numBytes == 0 || numBytes > 4 {
		return 0, 0, fmt.Errorf("ber: unsupported length field: %d bytes: %w",
			numBytes, errUnsupportedLengthField)
	}
	if offset+headerLen+numBytes > len(input) {
		return 0, 0, errTruncatedLongFormLength
	}
	var buf [4]byte
	copy(buf[4-numBytes:], input[offset+headerLen:offset+headerLen+numBytes])
	return int(binary.BigEndian.Uint32(buf[:])), headerLen + numBytes, nil
}

// writeTLV writes all tag bytes followed by the minimal definite-length DER
// encoding for the given content length. tagBytes must be the complete tag
// field as it appears in the input (one byte for short-form tags, two or more
// bytes for long-form tags with tag number ≥ 31).
func writeTLV(w *bytes.Buffer, tagBytes []byte, length int) {
	w.Write(tagBytes)
	switch {
	case length <= lenShortFormMax:
		w.WriteByte(byte(length)) //nolint:gosec // length ≤ 127 per case guard
	case length < 256:
		w.WriteByte(lenLongForm1Octet)
		w.WriteByte(byte(length)) //nolint:gosec // length < 256 per case guard
	case length < 65536:
		w.WriteByte(lenLongForm2Octets)
		w.WriteByte(byte(length >> 8)) //nolint:gosec // upper byte extracted via shift
		w.WriteByte(byte(length))      //nolint:gosec // lower byte; length < 65536 per case guard
	case length < 16777216:
		w.WriteByte(lenLongForm3Octets)
		w.WriteByte(byte(length >> 16)) //nolint:gosec // upper byte extracted via shift
		w.WriteByte(byte(length >> 8))  //nolint:gosec // middle byte extracted via shift
		w.WriteByte(byte(length))       //nolint:gosec // lower byte, mask applied implicitly
	default:
		w.WriteByte(lenLongForm4Octets)
		w.WriteByte(byte(length >> 24)) //nolint:gosec // highest byte extracted via shift
		w.WriteByte(byte(length >> 16)) //nolint:gosec // upper-middle byte extracted via shift
		w.WriteByte(byte(length >> 8))  //nolint:gosec // lower-middle byte extracted via shift
		w.WriteByte(byte(length))       //nolint:gosec // lowest byte, mask applied implicitly
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
		hdr, err := readHeader(content, pos)
		if err != nil {
			return nil, fmt.Errorf("ber: flatten: %w", err)
		}
		if hdr.indefinite {
			return nil, errNestedIndefinitePrimitive
		}
		valueStart := pos + hdr.headerLen
		valueEnd := valueStart + hdr.length
		if valueEnd > len(content) {
			return nil, errFlattenLengthExceeds
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
		hdr, err := readHeader(content, pos)
		if err != nil {
			return nil, fmt.Errorf("ber: flatten BIT STRING: %w", err)
		}
		if hdr.indefinite {
			return nil, errNestedIndefiniteBitString
		}
		valueStart := pos + hdr.headerLen
		valueEnd := valueStart + hdr.length
		if valueEnd > len(content) {
			return nil, errFlattenBitStringExceeds
		}
		chunk := content[valueStart:valueEnd]
		if len(chunk) == 0 {
			return nil, errBitStringMissingUnusedBits
		}
		isLast := valueEnd >= len(content)
		unused := chunk[0]
		if !isLast && unused != 0 {
			return nil, errNonFinalBitStringUnusedBits
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
		return nil, fmt.Errorf("ber: BOOLEAN value is %d bytes: %w", len(value), errBooleanLength)
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
		return nil, errIntegerEmpty
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
