package plan9

type Perm uint32

// Size is the type we use to encode 9P2000
type Size uint32

// Tag is the id field used to identify Transmit Messgaes
type Tag uint16

// MessageType is a single byte bit used to identified the type of message
type MessageType uint8

// FID is the id of the current file.
type FID uint32

const (
	// MSize is default message size (1048576+IOHdrSz)
	MSize = 2*1048576 + IOHDRSZ
	// IOHDRSZ non-data size of the Twrite messages
	IOHDRSZ = 24
	// DefaultVersion is the 9pversion
	DefaultVersion = "9P2000"

	NoTag Tag = ^Tag(0)
	NoFID     = 0xffffffff
	NoUID     = 0xffffffff
)

// A QID represents a 9P server's unique identification for a file.
type QID struct {
	Path uint64 // the file server's unique identification for the file
	Vers uint32 // version number for given Path
	Type uint8  // the type of the file (syscall.QTDIR for example)
}

// A Dir contains the metadata for a file.
type Dir struct {
	// system-modified data
	Type uint16 // server type
	Dev  uint32 // server subtype

	// file data
	QID    QID    // unique id from server
	Mode   Perm   // permissions
	Atime  uint32 // last read time
	Mtime  uint32 // last write time
	Length uint64 // file length
	Name   string // last element of path
	UID    string // owner name
	GID    string // group name
	Muid   string // last modifier name
}

// Message represents a 9P message
type Message interface {
	Size() Size
}
