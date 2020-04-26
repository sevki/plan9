package plan9

//go:generate bash -c "go run ./../../gen/gen.go > msgdecoders.go"
import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"

	"plan9.io"
)

const (
	tversion plan9.MessageType = 100 + iota
	rversion
	tauth
	rauth
	tattach
	rattach
	terror
	rerror
	tflush
	rflush
	twalk
	rwalk
	topen
	ropen
	tcreate
	rcreate
	tread
	rread
	twrite
	rwrite
	tclunk
	rclunk
	tremove
	rremove
	tstat
	rstat
	twstat
	rwstat
	tlast
)

// Each message consists of a sequence of bytes.
// Two–, four–, and eight–byte fields hold unsigned
// integers represented in little–endian order (least significant byte first).
var encoder = binary.LittleEndian

// Header is the standard header that is present in all 9P2000 messages.
type Header struct {
	size  plan9.Size
	mtype plan9.MessageType
	tag   plan9.Tag
}

// Decoder decodes 9P messsages.
type Decoder struct {
	r   io.Reader
	msg *Message
}

func NewDecoder(r io.Reader) *Decoder { return &Decoder{r: r} }

// Message is a generic 9P message
type Message interface{ encoding.BinaryUnmarshaler }
type ProtocolError string

func (e ProtocolError) Error() string {
	return string(e)
}

// Decode decodes messages 1by1
func Decode(r io.Reader) (Message, error) {
	data := make([]byte, 7)
	n, err := r.Read(data)
	if err != nil {
		return nil, fmt.Errorf("9p: read header: %v", err)
	}
	if n < 7 {
		return nil, fmt.Errorf("9p: header can't be less than 7 bytes: %v", io.EOF)
	}
	h := Header{}
	if err := h.UnmarshalBinary(data); err != nil {
		return nil, err
	}

	msg := newMessage(h)
	data = make([]byte, h.size)

	n, err = r.Read(data)
	if err == io.EOF && n == int(h.size)-7 {
		return msg, nil
	} else if err != nil {
		return nil, fmt.Errorf("9p: read body: %v", err)
	}
	if n < int(h.size)-7 {
		return nil, fmt.Errorf("9p: header can't be less than 7 bytes: %v", io.EOF)
	}
	msg.UnmarshalBinary(data)
	return msg, nil
}

func (h *Header) UnmarshalBinary(data []byte) error {
	h.size = plan9.Size(data[0]) | plan9.Size(data[1])<<8 | plan9.Size(data[2])<<16 | plan9.Size(data[3])<<24
	h.mtype = plan9.MessageType(data[4])
	h.tag = plan9.Tag(uint16(data[5]) | uint16(data[6])<<8)
	return nil
}

func (d *Decoder) unmarshall(x interface{}) error {
	v := reflect.ValueOf(x)
	s := v.Elem()
	st := s.Type()
	for i := 0; i < st.NumField(); i++ {
		var b []byte
		v := st.FieldByIndex([]int{i})
		sz := v.Type.Size()
		f := s.FieldByIndex([]int{i})
		if sz > 8 {
			goto SKIP
		}
		b = make([]byte, sz)
		d.r.Read(b)
	SKIP:
		switch sz {
		case 1:
			f.SetUint(uint64(b[0]))
		case 2:
			f.SetUint(uint64(encoder.Uint16(b)))
		case 4:
			f.SetUint(uint64(encoder.Uint32(b)))
		case 8:
			f.SetUint(encoder.Uint64(b))
		default:
			b = make([]byte, 2)
			d.r.Read(b)
			b = make([]byte, encoder.Uint16(b))
			d.r.Read(b)
			f.SetString(string(b))
		}
	}
	return nil
}

func unmarshallstring(data *[]byte, s *string) uint16 {
	size := uint16((*data)[0]) | uint16((*data)[1])<<8
	*s = string((*data)[2 : 2+size])
	*data = (*data)[2+size:]
	return size
}

var ErrStringMalformed = errors.New("string malformed")
