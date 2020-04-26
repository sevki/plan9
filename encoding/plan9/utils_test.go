package plan9

import (
	"aqwari.net/net/styx/styxproto"
	fuzz "github.com/google/gofuzz"
	"plan9.io"
)

var fuzzer = fuzz.New()

func fid() plan9.FID {
	f := plan9.FID(0)
	fuzzer.Fuzz(&f)
	return f
}
func qid() plan9.QID {
	q := plan9.QID{}
	fuzzer.Fuzz(&q.Path)
	fuzzer.Fuzz(&q.Type)
	fuzzer.Fuzz(&q.Vers)
	return q
}
func tag() plan9.Tag {
	tag := plan9.Tag(0)
	fuzzer.Fuzz(&tag)
	return tag
}

func dir() plan9.Dir {
	d := plan9.Dir{}
	fuzzer.Fuzz(&d)
	return d
}
func stat() (plan9.Dir, styxproto.Stat) {
	d := dir()
	buf := make([]byte, 13)
	qid, buf, err := styxproto.NewQid(buf, d.QID.Type, d.QID.Vers, d.QID.Path)
	buf = make([]byte, 2000)
	s, buf, err := styxproto.NewStat(buf, d.Name, d.UID, d.GID, d.Muid)
	if err != nil {
		panic(err)
	}
	s.SetQid(qid)
	s.SetAtime(d.Atime)
	s.SetMtime(d.Mtime)
	s.SetLength(int64(d.Length))
	s.SetDev(d.Dev)
	s.SetType(d.Type)
	s.SetMode(uint32(d.Mode))

	return d, s
}
