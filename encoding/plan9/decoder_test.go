package plan9

import (
	"bytes"
	"log"
	"math/rand"
	"time"

	"testing"

	"aqwari.net/net/styx/styxproto"
	"github.com/docker/docker/pkg/testutil/assert"
	fuzz "github.com/google/gofuzz"
	"plan9.io"
)

func TestDecoder_Decode(t *testing.T) {
	type fields struct {
		buf  []byte
		size int
		want Message
	}

	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "Tversion",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				enc.Tversion(plan9.MSize, plan9.DefaultVersion)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &VersionReq{
						header: Header{
							mtype: tversion,
							tag:   plan9.Tag(styxproto.NoTag),
							size:  plan9.Size(b.Len()),
						},
						msize:   plan9.MSize,
						version: plan9.DefaultVersion,
					},
				}
				return f
			}(),
		},
		{
			name: "Rversion",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				enc.Rversion(plan9.MSize, plan9.DefaultVersion)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &VersionResp{
						header: Header{
							mtype: rversion,
							tag:   plan9.Tag(styxproto.NoTag),
							size:  plan9.Size(b.Len()),
						},
						msize:   plan9.MSize,
						version: plan9.DefaultVersion,
					},
				}
				return f
			}(),
		},
		{
			name: "Tauth",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := 0
				afid := uint32(0)
				a := ""
				u := ""
				fzz.Fuzz(&tag)
				fzz.Fuzz(&afid)
				fzz.Fuzz(&a)
				fzz.Fuzz(&u)
				enc.Tauth(uint16(tag), afid, u, a)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &AuthReq{
						header: Header{
							mtype: tauth,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						afid:  plan9.FID(afid),
						uname: u,
						aname: a,
					},
				}
				return f
			}(),
		},
		{
			name: "Rauth",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				q := qid()
				tag := tag()
				fzz.Fuzz(&tag)
				buf := make([]byte, 13)
				qid, buf, err := styxproto.NewQid(buf, q.Type, q.Vers, q.Path)
				if err != nil {

				}
				enc.Rauth(uint16(tag), qid)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &AuthResp{
						header: Header{
							mtype: rauth,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						aqid: q,
					},
				}
				return f
			}(),
		},
		{
			name: "Rerror",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				fzz.Fuzz(&tag)
				ename := ""
				fzz.Fuzz(&ename)
				enc.Rerror(tag, ename)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &ErrorResp{
						header: Header{
							mtype: rerror,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						ename: ename,
					},
				}
				return f
			}(),
		},
		{
			name: "Tflush",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				oldtag := uint16(0)
				fzz.Fuzz(&tag)
				fzz.Fuzz(&oldtag)
				ename := ""
				fzz.Fuzz(&ename)
				enc.Tflush(tag, oldtag)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &FlushReq{
						header: Header{
							mtype: tflush,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						oldtag: plan9.Tag(oldtag),
					},
				}
				return f
			}(),
		},
		{
			name: "Rflush",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)

				fzz.Fuzz(&tag)

				ename := ""
				fzz.Fuzz(&ename)
				enc.Rflush(tag)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &FlushResp{
						header: Header{
							mtype: rflush,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
					},
				}
				return f
			}(),
		},
		{
			name: "Tattach",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				fid := uint32(0)
				afid := uint32(0)
				a := ""
				u := ""
				fzz.Fuzz(&tag)
				fzz.Fuzz(&afid)
				fzz.Fuzz(&fid)
				fzz.Fuzz(&a)
				fzz.Fuzz(&u)
				enc.Tattach(tag, fid, afid, u, a)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &AttachReq{
						header: Header{
							mtype: tattach,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						afid:  plan9.FID(afid),
						fid:   plan9.FID(fid),
						aname: a,
						uname: u,
					},
				}
				return f
			}(),
		},
		{
			name: "Rattach",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				q := plan9.QID{}
				fzz.Fuzz(&q.Path)
				fzz.Fuzz(&q.Type)
				fzz.Fuzz(&q.Vers)
				tag := uint16(0)
				fzz.Fuzz(&tag)
				buf := make([]byte, 13)
				qid, buf, err := styxproto.NewQid(buf, q.Type, q.Vers, q.Path)
				if err != nil {

				}
				enc.Rattach(tag, qid)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &AttachResp{
						header: Header{
							mtype: rattach,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						qid: q,
					},
				}
				return f
			}(),
		},
		{
			name: "Twalk",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				fid := uint32(0)
				afid := uint32(0)
				tag := uint16(0)
				rand.Seed(time.Now().Unix())
				s := []string{}
				for i := 0; i < rand.Intn(7)+3; i++ {
					sx := ""
					fzz.Fuzz(&sx)
					s = append(s, sx)
				}
				fzz.Fuzz(&tag)
				fzz.Fuzz(&afid)
				fzz.Fuzz(&fid)
				enc.Twalk(tag, fid, afid, s...)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &WalkReq{
						header: Header{
							mtype: twalk,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid:    plan9.FID(fid),
						newfid: plan9.FID(afid),
						wname:  s,
					},
				}
				return f
			}(),
		},
		{
			name: "Rwalk",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fzz.Fuzz(&tag)
				rand.Seed(time.Now().Unix())
				s := []plan9.QID{}
				qids := []styxproto.Qid{}

				for i := 0; i < rand.Intn(7)+3; i++ {
					q := plan9.QID{}
					fzz.Fuzz(&q.Path)
					fzz.Fuzz(&q.Type)
					fzz.Fuzz(&q.Vers)
					s = append(s, q)
					buf := make([]byte, 13)
					qid, buf, err := styxproto.NewQid(buf, q.Type, q.Vers, q.Path)
					if err != nil {

					}
					qids = append(qids, qid)
				}

				enc.Rwalk(tag, qids...)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &WalkResp{
						header: Header{
							mtype: rwalk,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						wqid: s,
					},
				}
				return f
			}(),
		},
		{
			name: "Topen",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				fid := plan9.FID(0)
				mode := uint8(0)
				fzz.Fuzz(&tag)
				fzz.Fuzz(&fid)
				fzz.Fuzz(&mode)
				enc.Topen(tag, uint32(fid), mode)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &OpenReq{
						header: Header{
							mtype: topen,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid:  fid,
						mode: mode,
					},
				}
				return f
			}(),
		},
		{
			name: "Ropen",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				iounit := uint32(0)
				fzz.Fuzz(&tag)
				q := plan9.QID{}
				fzz.Fuzz(&q.Path)
				fzz.Fuzz(&q.Type)
				fzz.Fuzz(&q.Vers)
				fzz.Fuzz(&iounit)
				buf := make([]byte, 13)
				qid, buf, err := styxproto.NewQid(buf, q.Type, q.Vers, q.Path)
				if err != nil {

				}

				enc.Ropen(tag, qid, iounit)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &OpenResp{
						header: Header{
							mtype: ropen,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						qid:    q,
						iounit: iounit,
					},
				}
				return f
			}(),
		},
		{
			name: "Tcreate",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)

				fzz := fuzz.New()

				tag := uint16(0)
				perm := uint32(0)
				mode := uint8(0)
				fid := plan9.FID(0)
				name := "sevki"
				fzz.Fuzz(&name)
				fzz.Fuzz(&tag)
				fzz.Fuzz(&fid)
				fzz.Fuzz(&mode)
				fzz.Fuzz(&perm)

				enc.Tcreate(tag, uint32(fid), name, perm, mode)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &CreateReq{
						header: Header{
							mtype: tcreate,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid:  fid,
						name: name,
						mode: mode,
						perm: perm,
					},
				}
				return f
			}(),
		},
		{
			name: "Rcreate",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				iounit := uint32(0)
				fzz.Fuzz(&tag)
				q := plan9.QID{}
				fzz.Fuzz(&q.Path)
				fzz.Fuzz(&q.Type)
				fzz.Fuzz(&q.Vers)
				fzz.Fuzz(&iounit)
				buf := make([]byte, 13)
				qid, buf, err := styxproto.NewQid(buf, q.Type, q.Vers, q.Path)
				if err != nil {

				}

				enc.Rcreate(tag, qid, iounit)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &CreateResp{
						header: Header{
							mtype: rcreate,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						qid:    q,
						iounit: iounit,
					},
				}
				return f
			}(),
		},
		{
			name: "Tread",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				count := uint32(0)
				offset := uint64(0)

				fzz.Fuzz(&fid)
				fzz.Fuzz(&count)
				fzz.Fuzz(&offset)
				fzz.Fuzz(&tag)

				enc.Tread(tag, uint32(fid), int64(offset), int64(count))
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &ReadReq{
						header: Header{
							mtype: tread,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid:    fid,
						count:  count,
						offset: offset,
					},
				}
				return f
			}(),
		},
		{
			name: "Rread",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				count := uint32(0)
				c := 50
				data := make([]byte, c)
				rand.Read(data)
				fzz.Fuzz(&fid)

				fzz.Fuzz(&tag)
				count = uint32(len(data))
				log.Println(count)
				enc.Rread(tag, data)
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &ReadResp{
						header: Header{
							mtype: rread,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						data: data,
					},
				}
				return f
			}(),
		},
		{
			name: "Twrite",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				offset := uint64(0)
				c := 50
				data := make([]byte, c)
				rand.Read(data)
				fzz.Fuzz(&fid)
				fzz.Fuzz(&offset)
				fzz.Fuzz(&tag)
				enc.Twrite(tag, uint32(fid), int64(offset), data)
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &WriteReq{
						header: Header{
							mtype: twrite,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid:    fid,
						offset: offset,
						data:   data,
					},
				}
				return f
			}(),
		},
		{
			name: "Rwrite",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				count := uint32(0)
				c := 50
				data := make([]byte, c)
				rand.Read(data)
				fzz.Fuzz(&fid)
				//	fzz.Fuzz(&data)
				fzz.Fuzz(&count)

				fzz.Fuzz(&tag)
				enc.Rwrite(tag, int64(count))
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &WriteResp{
						header: Header{
							mtype: rwrite,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						count: count,
					},
				}
				return f
			}(),
		},
		{
			name: "Tclunk",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				count := uint32(0)
				c := 50
				data := make([]byte, c)
				rand.Read(data)
				fzz.Fuzz(&fid)
				//	fzz.Fuzz(&data)
				fzz.Fuzz(&count)

				fzz.Fuzz(&tag)
				enc.Tclunk(tag, uint32(fid))
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &ClunkReq{
						header: Header{
							mtype: tclunk,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid: fid,
					},
				}
				return f
			}(),
		},
		{
			name: "Rclunk",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				fzz.Fuzz(&fid)

				fzz.Fuzz(&tag)
				enc.Rclunk(tag)
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &ClunkResp{
						header: Header{
							mtype: rclunk,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
					},
				}
				return f
			}(),
		},
		{
			name: "Tremove",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fid := plan9.FID(0)
				fzz.Fuzz(&fid)
				fzz.Fuzz(&tag)
				enc.Tremove(tag, uint32(fid))
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &RemoveReq{
						header: Header{
							mtype: tremove,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid: fid,
					},
				}
				return f
			}(),
		},
		{
			name: "Rremove",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()

				tag := uint16(0)
				fzz.Fuzz(&tag)
				enc.Rremove(tag)
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &RemoveResp{
						header: Header{
							mtype: rremove,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
					},
				}
				return f
			}(),
		},
		{
			name: "Tstat",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				fzz := fuzz.New()
				tag := uint16(0)
				fid := plan9.FID(0)
				fzz.Fuzz(&fid)
				fzz.Fuzz(&tag)
				enc.Tstat(tag, uint32(fid))
				enc.Flush()

				f := fields{
					buf: b.Bytes(),
					want: &StatReq{
						header: Header{
							mtype: tstat,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						fid: fid,
					},
				}
				return f
			}(),
		},
		{
			name: "Rstat",
			fields: func() fields {
				b := bytes.NewBuffer(nil)
				enc := styxproto.NewEncoder(b)
				d, s := stat()

				tag := tag()
				enc.Rstat(uint16(tag), s)
				enc.Flush()
				f := fields{
					buf: b.Bytes(),
					want: &StatResp{
						header: Header{
							mtype: rstat,
							tag:   plan9.Tag(tag),
							size:  plan9.Size(b.Len()),
						},
						stat: &d,
					},
				}
				return f
			}(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if msg, err := Decode(bytes.NewBuffer(tt.fields.buf)); (err != nil) != tt.wantErr {
				t.Errorf("Decoder.Decode() error = %v, wantErr %v", err, tt.wantErr)
			} else {
				switch rr := msg.(type) {
				default:
					_ = rr
					assert.DeepEqual(t, msg, tt.fields.want)
				}

			}
		})
	}
}

func BenchmarkHardcoded(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer([]byte{19, 0, 0, 0, 100, 0x55, 0xaa, 0, 32, 0, 0, 6, 0, 57, 80, 50, 48, 48, 48})
		_, _ = Decode(buf)
	}
}

type versionReq struct {
	Size     plan9.Size        // 4 bytes
	Tversion plan9.MessageType // 1 byte
	Tag      plan9.Tag         // 2 bytes
	MaxSize  uint32            // 4 bytes
	Version  string            // 8 bytes (almost definitely probably)
}

func BenchmarkReflected(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := bytes.NewBuffer([]byte{19, 0, 0, 0, 100, 0x55, 0xaa, 0, 32, 0, 0, 6, 0, 57, 80, 50, 48, 48, 48})
		d := Decoder{r: buf}
		_ = d
		msg := &versionReq{}
		d.unmarshall(msg)
	}
}
