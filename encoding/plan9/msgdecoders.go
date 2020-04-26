package plan9

import "plan9.io"

// VersionReq is a 9P Tversion message
//
// 	size[4] Tversion tag[2] msize[4] version[s]
//
type VersionReq struct {
	header  Header
	msize   uint32
	version string
}

func (v *VersionReq) UnmarshalBinary(data []byte) error {
	v.msize, data = guint32(data)
	v.version, data = gstring(data)
	return nil
}

// VersionResp is a 9P Rversion message
//
// 	size[4] Rversion tag[2] msize[4] version[s]
//
type VersionResp struct {
	header  Header
	msize   uint32
	version string
}

func (v *VersionResp) UnmarshalBinary(data []byte) error {
	v.msize, data = guint32(data)
	v.version, data = gstring(data)
	return nil
}

// AuthReq is a 9P Tauth message
//
// 	size[4] Tauth tag[2] afid[4] uname[s] aname[s]
//
type AuthReq struct {
	header Header
	afid   plan9.FID
	uname  string
	aname  string
}

func (a *AuthReq) UnmarshalBinary(data []byte) error {
	a.afid, data = gfid(data)
	a.uname, data = gstring(data)
	a.aname, data = gstring(data)
	return nil
}

// AuthResp is a 9P Rauth message
//
// 	size[4] Rauth tag[2] aqid[13]
//
type AuthResp struct {
	header Header
	aqid   plan9.QID
}

func (a *AuthResp) UnmarshalBinary(data []byte) error {
	a.aqid.Type, data = guint8(data)
	a.aqid.Vers, data = guint32(data)
	a.aqid.Path, data = guint64(data)
	return nil
}

// ErrorResp is a 9P Rerror message
//
// 	size[4] Rerror tag[2] ename[s]
//
type ErrorResp struct {
	header Header
	ename  string
}

func (e *ErrorResp) UnmarshalBinary(data []byte) error {
	e.ename, data = gstring(data)
	return nil
}

// FlushReq is a 9P Tflush message
//
// 	size[4] Tflush tag[2] oldtag[2]
//
type FlushReq struct {
	header Header
	oldtag plan9.Tag
}

func (f *FlushReq) UnmarshalBinary(data []byte) error {
	f.oldtag, data = gtag(data)
	return nil
}

// FlushResp is a 9P Rflush message
//
// 	size[4] Rflush tag[2]
//
type FlushResp struct {
	header Header
}

func (f *FlushResp) UnmarshalBinary(data []byte) error {
	return nil
}

// AttachReq is a 9P Tattach message
//
// 	size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
//
type AttachReq struct {
	header Header
	fid    plan9.FID
	afid   plan9.FID
	uname  string
	aname  string
}

func (a *AttachReq) UnmarshalBinary(data []byte) error {
	a.fid, data = gfid(data)
	a.afid, data = gfid(data)
	a.uname, data = gstring(data)
	a.aname, data = gstring(data)
	return nil
}

// AttachResp is a 9P Rattach message
//
// 	size[4] Rattach tag[2] qid[13]
//
type AttachResp struct {
	header Header
	qid    plan9.QID
}

func (a *AttachResp) UnmarshalBinary(data []byte) error {
	a.qid.Type, data = guint8(data)
	a.qid.Vers, data = guint32(data)
	a.qid.Path, data = guint64(data)
	return nil
}

// WalkReq is a 9P Twalk message
//
// 	size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
//
type WalkReq struct {
	header Header
	fid    plan9.FID
	newfid plan9.FID
	wname  []string
}

func (w *WalkReq) UnmarshalBinary(data []byte) error {
	w.fid, data = gfid(data)
	w.newfid, data = gfid(data)
	var nwname uint16
	nwname, data = guint16(data)
	for i := uint16(0); i < nwname; i++ {
		var s string
		s, data = gstring(data)
		w.wname = append(w.wname, s)
	}
	return nil
}

// WalkResp is a 9P Rwalk message
//
// 	size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
//
type WalkResp struct {
	header Header
	wqid   []plan9.QID
}

func (w *WalkResp) UnmarshalBinary(data []byte) error {
	var nwname uint16
	nwname, data = guint16(data)
	for i := uint16(0); i < nwname; i++ {
		var q plan9.QID
		q.Type, data = guint8(data)
		q.Vers, data = guint32(data)
		q.Path, data = guint64(data)
		w.wqid = append(w.wqid, q)
	}
	return nil
}

// OpenReq is a 9P Topen message
//
// 	size[4] Topen tag[2] fid[4] mode[1]
//
type OpenReq struct {
	header Header
	fid    plan9.FID
	mode   uint8
}

func (o *OpenReq) UnmarshalBinary(data []byte) error {
	o.fid, data = gfid(data)
	o.mode, data = guint8(data)
	return nil
}

// OpenResp is a 9P Ropen message
//
// 	size[4] Ropen tag[2] qid[13] iounit[4]
//
type OpenResp struct {
	header Header
	qid    plan9.QID
	iounit uint32
}

func (o *OpenResp) UnmarshalBinary(data []byte) error {
	o.qid.Type, data = guint8(data)
	o.qid.Vers, data = guint32(data)
	o.qid.Path, data = guint64(data)
	o.iounit, data = guint32(data)
	return nil
}

// CreateReq is a 9P Tcreate message
//
// 	size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
//
type CreateReq struct {
	header Header
	fid    plan9.FID
	name   string
	perm   uint32
	mode   uint8
}

func (c *CreateReq) UnmarshalBinary(data []byte) error {
	c.fid, data = gfid(data)
	c.name, data = gstring(data)
	c.perm, data = guint32(data)
	c.mode, data = guint8(data)
	return nil
}

// CreateResp is a 9P Rcreate message
//
// 	size[4] Rcreate tag[2] qid[13] iounit[4]
//
type CreateResp struct {
	header Header
	qid    plan9.QID
	iounit uint32
}

func (c *CreateResp) UnmarshalBinary(data []byte) error {
	c.qid.Type, data = guint8(data)
	c.qid.Vers, data = guint32(data)
	c.qid.Path, data = guint64(data)
	c.iounit, data = guint32(data)
	return nil
}

// ReadReq is a 9P Tread message
//
// 	size[4] Tread tag[2] fid[4] offset[8] count[4]
//
type ReadReq struct {
	header Header
	fid    plan9.FID
	offset uint64
	count  uint32
}

func (r *ReadReq) UnmarshalBinary(data []byte) error {
	r.fid, data = gfid(data)
	r.offset, data = guint64(data)
	r.count, data = guint32(data)
	return nil
}

// ReadResp is a 9P Rread message
//
// 	size[4] Rread tag[2] count[4] data[count]
//
type ReadResp struct {
	header Header
	data   []byte
}

func (r *ReadResp) UnmarshalBinary(data []byte) error {
	var count uint32
	count, data = guint32(data)
	r.data = data[:count]
	return nil
}

// WriteReq is a 9P Twrite message
//
// 	size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
//
type WriteReq struct {
	header Header
	fid    plan9.FID
	offset uint64
	data   []byte
}

func (w *WriteReq) UnmarshalBinary(data []byte) error {
	w.fid, data = gfid(data)
	w.offset, data = guint64(data)
	var count uint32
	count, data = guint32(data)
	w.data = data[:count]
	return nil
}

// WriteResp is a 9P Rwrite message
//
// 	size[4] Rwrite tag[2] count[4]
//
type WriteResp struct {
	header Header
	count  uint32
}

func (w *WriteResp) UnmarshalBinary(data []byte) error {
	w.count, data = guint32(data)
	return nil
}

// ClunkReq is a 9P Tclunk message
//
// 	size[4] Tclunk tag[2] fid[4]
//
type ClunkReq struct {
	header Header
	fid    plan9.FID
}

func (c *ClunkReq) UnmarshalBinary(data []byte) error {
	c.fid, data = gfid(data)
	return nil
}

// ClunkResp is a 9P Rclunk message
//
// 	size[4] Rclunk tag[2]
//
type ClunkResp struct {
	header Header
}

func (c *ClunkResp) UnmarshalBinary(data []byte) error {
	return nil
}

// RemoveReq is a 9P Tremove message
//
// 	size[4] Tremove tag[2] fid[4]
//
type RemoveReq struct {
	header Header
	fid    plan9.FID
}

func (r *RemoveReq) UnmarshalBinary(data []byte) error {
	r.fid, data = gfid(data)
	return nil
}

// RemoveResp is a 9P Rremove message
//
// 	size[4] Rremove tag[2]
//
type RemoveResp struct {
	header Header
}

func (r *RemoveResp) UnmarshalBinary(data []byte) error {
	return nil
}

// StatReq is a 9P Tstat message
//
// 	size[4] Tstat tag[2] fid[4]
//
type StatReq struct {
	header Header
	fid    plan9.FID
}

func (s *StatReq) UnmarshalBinary(data []byte) error {
	s.fid, data = gfid(data)
	return nil
}

// StatResp is a 9P Rstat message
//
// 	size[4] Rstat tag[2] stat[n]
//
type StatResp struct {
	header Header
	stat   *plan9.Dir
}

func (s *StatResp) UnmarshalBinary(data []byte) error {
	_, data = guint16(data) // BUG(sevki): see https://9p.io/magic/man2html/5/stat
	s.stat, data = unmarshaldir(data)
	return nil
}

// WstatReq is a 9P Twstat message
//
// 	size[4] Twstat tag[2] fid[4] stat[n]
//
type WstatReq struct {
	header Header
	fid    plan9.FID
	stat   *plan9.Dir
}

func (w *WstatReq) UnmarshalBinary(data []byte) error {
	w.fid, data = gfid(data)
	_, data = guint16(data) // BUG(sevki): see https://9p.io/magic/man2html/5/stat
	w.stat, data = unmarshaldir(data)
	return nil
}

// WstatResp is a 9P Rwstat message
//
// 	size[4] Rwstat tag[2]
//
type WstatResp struct {
	header Header
}

func (w *WstatResp) UnmarshalBinary(data []byte) error {
	return nil
}

func newMessage(h Header) Message {
	var msg Message
	switch h.mtype {
	case tversion:
		return &VersionReq{header: h}
	case rversion:
		return &VersionResp{header: h}
	case tauth:
		return &AuthReq{header: h}
	case rauth:
		return &AuthResp{header: h}
	case rerror:
		return &ErrorResp{header: h}
	case tflush:
		return &FlushReq{header: h}
	case rflush:
		return &FlushResp{header: h}
	case tattach:
		return &AttachReq{header: h}
	case rattach:
		return &AttachResp{header: h}
	case twalk:
		return &WalkReq{header: h}
	case rwalk:
		return &WalkResp{header: h}
	case topen:
		return &OpenReq{header: h}
	case ropen:
		return &OpenResp{header: h}
	case tcreate:
		return &CreateReq{header: h}
	case rcreate:
		return &CreateResp{header: h}
	case tread:
		return &ReadReq{header: h}
	case rread:
		return &ReadResp{header: h}
	case twrite:
		return &WriteReq{header: h}
	case rwrite:
		return &WriteResp{header: h}
	case tclunk:
		return &ClunkReq{header: h}
	case rclunk:
		return &ClunkResp{header: h}
	case tremove:
		return &RemoveReq{header: h}
	case rremove:
		return &RemoveResp{header: h}
	case tstat:
		return &StatReq{header: h}
	case rstat:
		return &StatResp{header: h}
	case twstat:
		return &WstatReq{header: h}
	case rwstat:
		return &WstatResp{header: h}
	}
	return msg
}
