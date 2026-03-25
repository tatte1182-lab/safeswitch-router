package dns

import (
"encoding/binary"
"errors"
"strings"
)

type msg struct {
id        uint16
flags     uint16
qdCount   uint16
questions []question
body      []byte
}

type question struct {
name  string
qtype uint16
class uint16
}

var errShort = errors.New("dns: message too short")

func parseQuery(b []byte) (*msg, error) {
if len(b) < 12 {
return nil, errShort
}
m := &msg{
id:      binary.BigEndian.Uint16(b[0:2]),
flags:   binary.BigEndian.Uint16(b[2:4]),
qdCount: binary.BigEndian.Uint16(b[4:6]),
body:    b,
}
offset := 12
for i := 0; i < int(m.qdCount); i++ {
name, n, err := readName(b, offset)
if err != nil {
return nil, err
}
offset += n
if offset+4 > len(b) {
return nil, errShort
}
m.questions = append(m.questions, question{
name:  name,
qtype: binary.BigEndian.Uint16(b[offset : offset+2]),
class: binary.BigEndian.Uint16(b[offset+2 : offset+4]),
})
offset += 4
}
return m, nil
}

func buildNXDomain(query []byte) []byte {
if len(query) < 12 {
return nil
}
resp := make([]byte, len(query))
copy(resp, query)
flags := binary.BigEndian.Uint16(query[2:4])
flags |= 0x8000
flags |= 0x0080
flags |= 0x0003
binary.BigEndian.PutUint16(resp[2:4], flags)
binary.BigEndian.PutUint16(resp[6:8], 0)
binary.BigEndian.PutUint16(resp[8:10], 0)
binary.BigEndian.PutUint16(resp[10:12], 0)
return resp
}

func buildServFail(query []byte) []byte {
if len(query) < 12 {
return nil
}
resp := make([]byte, 12)
copy(resp, query[:12])
flags := binary.BigEndian.Uint16(query[2:4])
flags |= 0x8000
flags = (flags & 0xFFF0) | 0x0002
binary.BigEndian.PutUint16(resp[2:4], flags)
for i := 4; i < 12; i++ {
resp[i] = 0
}
return resp
}

func readName(b []byte, offset int) (string, int, error) {
var labels []string
start := offset
visited := 0
for {
if offset >= len(b) {
return "", 0, errShort
}
length := int(b[offset])
if length == 0 {
offset++
break
}
if length&0xC0 == 0xC0 {
if offset+1 >= len(b) {
return "", 0, errShort
}
ptr := int(binary.BigEndian.Uint16([]byte{b[offset] & 0x3F, b[offset+1]}))
offset += 2
if visited == 0 {
visited = offset - start
}
offset = ptr
continue
}
offset++
if offset+length > len(b) {
return "", 0, errShort
}
labels = append(labels, string(b[offset:offset+length]))
offset += length
}
consumed := offset - start
if visited > 0 {
consumed = visited
}
return strings.Join(labels, "."), consumed, nil
}
