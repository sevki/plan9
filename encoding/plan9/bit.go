package plan9

import (
	"plan9.io"
)

func guint8(b []byte) (uint8, []byte) {
	return uint8(b[0]), b[1:]
}

func guint16(b []byte) (uint16, []byte) {
	return uint16(b[0]) | uint16(b[1])<<8, b[2:]
}

func guint32(b []byte) (uint32, []byte) {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24, b[4:]
}

func guint64(b []byte) (uint64, []byte) {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56, b[8:]
}

func gstring(b []byte) (string, []byte) {
	n, b := guint16(b)
	return string(b[0:n]), b[n:]
}

func pbit8(b []byte, x uint8) []byte {
	n := len(b)
	if n+1 > cap(b) {
		nb := make([]byte, n, 100+2*cap(b))
		copy(nb, b)
		b = nb
	}
	b = b[0 : n+1]
	b[n] = x
	return b
}

func pbit16(b []byte, x uint16) []byte {
	n := len(b)
	if n+2 > cap(b) {
		nb := make([]byte, n, 100+2*cap(b))
		copy(nb, b)
		b = nb
	}
	b = b[0 : n+2]
	b[n] = byte(x)
	b[n+1] = byte(x >> 8)
	return b
}

func pbit32(b []byte, x uint32) []byte {
	n := len(b)
	if n+4 > cap(b) {
		nb := make([]byte, n, 100+2*cap(b))
		copy(nb, b)
		b = nb
	}
	b = b[0 : n+4]
	b[n] = byte(x)
	b[n+1] = byte(x >> 8)
	b[n+2] = byte(x >> 16)
	b[n+3] = byte(x >> 24)
	return b
}

func pbit64(b []byte, x uint64) []byte {
	b = pbit32(b, uint32(x))
	b = pbit32(b, uint32(x>>32))
	return b
}

func pstring(b []byte, s string) []byte {
	if len(s) >= 1<<16 {
		panic("string too long")
	}
	b = pbit16(b, uint16(len(s)))
	b = append(b, []byte(s)...)
	return b
}
func gtag(b []byte) (plan9.Tag, []byte) {
	return plan9.Tag(b[0]) | plan9.Tag(b[1])<<8, b[2:]
}

func gfid(b []byte) (plan9.FID, []byte) {
	var t uint32
	t, b = guint32(b)
	return plan9.FID(t), b
}
func unmarshaldir(b []byte) (*plan9.Dir, []byte) {
	n, b := guint16(b)
	if int(n) > len(b) {
		panic(1)
	}
	d := new(plan9.Dir)
	d.Type, b = guint16(b)
	d.Dev, b = guint32(b)
	d.QID, b = gqid(b)
	d.Mode, b = gperm(b)
	d.Atime, b = guint32(b)
	d.Mtime, b = guint32(b)
	d.Length, b = guint64(b)
	d.Name, b = gstring(b)
	d.UID, b = gstring(b)
	d.GID, b = gstring(b)
	d.Muid, b = gstring(b)
	return d, b
}
func gqid(b []byte) (plan9.QID, []byte) {
	var q plan9.QID
	q.Type, b = guint8(b)
	q.Vers, b = guint32(b)
	q.Path, b = guint64(b)
	return q, b
}
func gperm(b []byte) (plan9.Perm, []byte) {
	p, b := guint32(b)
	return plan9.Perm(p), b
}
