package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"golang.org/x/tools/imports"
)

const calls = `size[4] Tversion tag[2] msize[4] version[s]
size[4] Rversion tag[2] msize[4] version[s]
size[4] Tauth tag[2] afid[4] uname[s] aname[s]
size[4] Rauth tag[2] aqid[13]
size[4] Rerror tag[2] ename[s]
size[4] Tflush tag[2] oldtag[2]
size[4] Rflush tag[2]
size[4] Tattach tag[2] fid[4] afid[4] uname[s] aname[s]
size[4] Rattach tag[2] qid[13]
size[4] Twalk tag[2] fid[4] newfid[4] nwname[2] nwname*(wname[s])
size[4] Rwalk tag[2] nwqid[2] nwqid*(wqid[13])
size[4] Topen tag[2] fid[4] mode[1]
size[4] Ropen tag[2] qid[13] iounit[4]
size[4] Tcreate tag[2] fid[4] name[s] perm[4] mode[1]
size[4] Rcreate tag[2] qid[13] iounit[4]
size[4] Tread tag[2] fid[4] offset[8] count[4]
size[4] Rread tag[2] count[4] data[count]
size[4] Twrite tag[2] fid[4] offset[8] count[4] data[count]
size[4] Rwrite tag[2] count[4]
size[4] Tclunk tag[2] fid[4]
size[4] Rclunk tag[2]
size[4] Tremove tag[2] fid[4]
size[4] Rremove tag[2]
size[4] Tstat tag[2] fid[4]
size[4] Rstat tag[2] stat[n]
size[4] Twstat tag[2] fid[4] stat[n]
size[4] Rwstat tag[2]`

func main() {
	scanner := bufio.NewScanner(strings.NewReader(calls))
	// Set the split function for the scanning operation.
	scanner.Split(bufio.ScanWords)
	// Count the words.

	line := stract{}
	lines := pkg{}
	first := true
	for scanner.Scan() {
		t := scanner.Text()

		if t == "size[4]" && !first {
			lines = append(lines, line)

			line = stract{}
		}
		line.spec += " " + t
		first = false

		frags := strings.Split(t, "[")
		fieldName, size := t, 1
		if len(frags) > 1 {
			fieldName = frags[0]
			i, err := strconv.Atoi(strings.Trim(frags[1], "])"))
			if err == nil {
				size = i
			} else if frags[1] == "n]" {
				size = -3
			} else if frags[1] == "count]" {
				size = -6
			} else if frags[1] == "s]" {
				size = -1
			} else {
				size = -2
			}
		}
		line.fields = append(line.fields, field{fieldName, size, 0, ""})

	}
	lines = append(lines, line)
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading input:", err)
	}

	for j, l := range lines {
		size := 0
		for i, f := range l.fields {
			if f.name[0] == 'R' || f.name[0] == 'T' {
				lines[j].name = strings.ToUpper(string(f.name[1:2])) + f.name[2:]
				l.fields[i].name = "MessageType"
				lines[j].req = f.name[0] == 'R'
			}
			if f.size == -6 {
				l.fields[i].typ = "[]byte"
			}
			if f.size == -1 {
				l.fields[i].typ = "string"
			}
			if f.size == -3 {
				l.fields[i].typ = "*plan9.Dir"
			}
			if f.size == 1 {
				l.fields[i].typ = "uint8"
			}
			if f.size == 2 {
				l.fields[i].typ = "uint16"
			}
			if f.size == 4 {
				l.fields[i].typ = "uint32"
			}
			if f.size == 8 {
				l.fields[i].typ = "uint64"
			}
			if strings.HasSuffix(l.fields[i].name, "fid") {
				l.fields[i].typ = "plan9.FID"
			}
			if strings.HasSuffix(l.fields[i].name, "qid") {
				l.fields[i].typ = "plan9.QID"
			}
			if strings.HasSuffix(l.fields[i].name, "tag") {
				l.fields[i].typ = "plan9.Tag"
			}

			l.fields[i].offset = size
			size = size + f.size
		}
		if lines[j].name == "Walk" {
			if !lines[j].req {
				lines[j].fields = append(l.fields[:len(l.fields)-2], field{"wname", -4, 0, "[]string"})
			} else {
				lines[j].fields = append(l.fields[:len(l.fields)-2], field{"wqid", -5, 0, "[]plan9.QID"})
			}
		}
	}
	buf := bytes.NewBuffer(nil)
	io.WriteString(buf, "package plan9\n")
	fmt.Fprintln(buf, lines)

	fmt.Fprintf(buf, `func newMessage(h Header) Message{
 	var msg Message
switch h.mtype {
`)
	for _, s := range lines {
		fmt.Fprintf(buf, `case %s:
return &%s{header: h}
`, s.Enum(), s.Name())
	}
	fmt.Fprintf(buf, `}
return msg
}`)
	opts := imports.Options{
		Fragment:  true,
		AllErrors: false, // Report all errors (not just the first 10 on different lines)

		Comments:  true, // Print comments (true if nil *Options provided)
		TabIndent: true, // Use tabs for indent (true if nil *Options provided)
		TabWidth:  8,    // Tab width (8 if nil *Options provided)

		FormatOnly: false, // Disable the insertion and deletion of imports
	}
	bytz, err := imports.Process("/home/sevki/src/9p/encoding/plan9/msgdecoders.go", buf.Bytes(), &opts)
	if err != nil {
		log.Println(err)
		os.Stdout.Write(buf.Bytes())
	}

	os.Stdout.Write(bytz)
}

type pkg []stract

func (f pkg) String() string {
	buf := bytes.NewBuffer(nil)
	for _, strct := range f {
		fmt.Fprint(buf, strct)
	}
	return buf.String()
}

type stract struct {
	name   string
	fields []field
	req    bool
	spec   string
}
type field struct {
	name   string
	size   int
	offset int
	typ    string
}

func (s stract) Enum() string {
	req := "r"
	if !s.req {
		req = "t"
	}
	name := req + strings.ToLower(s.name)
	return name
}
func (s stract) Name() string {
	req := "Resp"
	if !s.req {
		req = "Req"
	}
	name := s.name + req
	return name
}
func (f field) String() string {
	return fmt.Sprintf("\t%s\t%s", f.name, f.typ)
}
func (s stract) String() string {
	buf := bytes.NewBuffer(nil)
	req := "Resp"
	t := "R"
	if !s.req {
		req = "Req"
		t = "T"
	}
	name := s.name + req
	fmt.Fprintf(buf, `// %s is a 9P %s message
//
// 	%s
// 
type %s struct `, name, t+strings.ToLower(s.name), s.spec[1:], name)
	fmt.Fprintln(buf, "{")
	fmt.Fprintln(buf, "\theader\tHeader")
	for _, f := range s.fields[3:] {
		if ((s.name == "Read" && s.req) || (s.name == "Write" && !s.req)) && f.name == "count" {
			continue
		}
		fmt.Fprintln(buf, f)
	}
	fmt.Fprintln(buf, "}")
	inital := strings.ToLower(name[:1])
	fmt.Fprintf(buf, "func (%s *%s) UnmarshalBinary(data []byte) error{\n", inital, name)
	offset := 0
	nextByte := func() string {
		defer func() { offset = offset + 1 }()
		return fmt.Sprintf("data[%d]", offset)
	}
	nfileds := []field{}
	for i, fyld := range s.fields[3:] {
		switch fyld.size {
		case -6:
			nfileds = append(nfileds[:i-1], fyld)
		case 13:
			nfileds = append(nfileds, field{fyld.name + ".Type", 1, fyld.offset + 12, "uint8"})
			nfileds = append(nfileds, field{fyld.name + ".Vers", 4, fyld.offset + 8, "uint32"})
			nfileds = append(nfileds, field{fyld.name + ".Path", 8, fyld.offset, "uint64"})
		default:
			nfileds = append(nfileds, fyld)
		}
	}
	for _, fyld := range nfileds {
		typ := strings.Replace(fyld.typ, ".", "", -1)
		typ = strings.Replace(typ, "[]", "", -1)
		unmarshaller := ""
		switch fyld.size {
		case 1, 2, 4, 8:
			/*
				s := []string{}
				for i := 0; i < fyld.size; i++ {
					x := nextByte()
					x = fmt.Sprintf("%s(%s)", fyld.typ, x)
					if i > 0 {
						x = fmt.Sprintf("%s<<%d", x, i*8)
					}

					s = append(s, x)
				}
				unmarshaller = strings.Join(s, "|")
			*/
			typ := strings.Replace(fyld.typ, "plan9.", "", -1)
			unmarshaller = fmt.Sprintf("g%s(data)", strings.ToLower(typ))
			fmt.Fprintf(buf, "%s.%s, data=%s\n", inital, fyld.name, unmarshaller)
		case -1:
			unmarshaller = "gstring(data)"
			fmt.Fprintf(buf, "%s.%s, data=%s\n", inital, fyld.name, unmarshaller)
			continue
		case -3:
			unmarshaller = "unmarshaldir(data)"
			fmt.Fprintf(buf, "_, data = guint16(data) // BUG(sevki): see https://9p.io/magic/man2html/5/stat\n")
			fmt.Fprintf(buf, "%s.%s, data=%s\n", inital, fyld.name, unmarshaller)
		case -4:
			unmarshaller = "gstring(data)"
			fmt.Fprintf(buf, "var nwname uint16;nwname, data=guint16(data)\n")
			fmt.Fprintf(buf, "for i:= uint16(0); i< nwname; i++{\n")
			fmt.Fprintf(buf, "var s string;s, data = gstring(data);%s.%s = append(%s.%s , s)", inital, fyld.name, inital, fyld.name)
			fmt.Fprintf(buf, "}\n")
			continue
		case -5:
			unmarshaller = "gstring(data)"
			fmt.Fprintf(buf, "var nwname uint16;nwname, data=guint16(data)\n")
			fmt.Fprintf(buf, "for i:= uint16(0); i< nwname; i++{\n")
			fmt.Fprintf(buf, "var q plan9.QID;")
			fmt.Fprintf(buf, "q.Type, data = guint8(data);")
			fmt.Fprintf(buf, "q.Vers, data = guint32(data);")
			fmt.Fprintf(buf, "q.Path, data = guint64(data);")
			fmt.Fprintf(buf, "%s.%s = append(%s.%s , q)", inital, fyld.name, inital, fyld.name)
			fmt.Fprintf(buf, "}\n")
			continue
		case -6:
			unmarshaller = "gstring(data)"
			fmt.Fprintf(buf, "var count uint32;count , data=guint32(data)\n")
			fmt.Fprintf(buf, "%s.%s = data[:count ]\n", inital, fyld.name)
			continue
		default:
			for i := 0; i < fyld.size; i++ {
				nextByte()
			}
			continue
		}

	}
	fmt.Fprintln(buf, "return nil")
	fmt.Fprintln(buf, "}")
	return buf.String()
}
