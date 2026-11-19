package sfu

import (
	"encoding/binary"
	"testing"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

func rewriteTestPublisher() *endpoint {
	return &endpoint{
		kind: EndpointMain,
		plan: buildMediaPlan(ClientOffer{
			AudioSSRC: 1000,
			SsrcGroups: []SsrcGroup{
				{Semantics: "SIM", Sources: []uint32{1001, 1003}},
				{Semantics: "FID", Sources: []uint32{1001, 1002}},
				{Semantics: "FID", Sources: []uint32{1003, 1004}},
			},
		}),
	}
}

// vp8Packet 构造带 15 位 picture id 与 TL0PICIDX 的 VP8 RTP 包。
func vp8Packet(t *testing.T, ssrc uint32, seq uint16, ts uint32, pic uint16, tl0 uint8, key bool) []byte {
	t.Helper()
	frame := byte(0x01) // 非关键帧
	if key {
		frame = 0x00
	}
	payload := []byte{0x90, 0xC0, 0x80 | byte(pic>>8), byte(pic), tl0, frame, 0xAA}
	raw, err := (&rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: vp8PayloadType, SequenceNumber: seq, Timestamp: ts, SSRC: ssrc},
		Payload: payload,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rtxPacket(t *testing.T, ssrc uint32, seq uint16, ts uint32, osn uint16, inner []byte) []byte {
	t.Helper()
	payload := make([]byte, 2+len(inner))
	binary.BigEndian.PutUint16(payload, osn)
	copy(payload[2:], inner)
	raw, err := (&rtp.Packet{
		Header:  rtp.Header{Version: 2, PayloadType: vp8RTXPayloadType, SequenceNumber: seq, Timestamp: ts, SSRC: ssrc},
		Payload: payload,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type parsedOut struct {
	ssrc uint32
	seq  uint16
	ts   uint32
	pic  uint16
	tl0  uint8
}

func parseOut(t *testing.T, raw []byte) parsedOut {
	t.Helper()
	var pkt rtp.Packet
	if err := pkt.Unmarshal(raw); err != nil {
		t.Fatal(err)
	}
	return parsedOut{
		ssrc: pkt.SSRC,
		seq:  pkt.SequenceNumber,
		ts:   pkt.Timestamp,
		pic:  readVP8PictureID(pkt.Payload[2:]),
		tl0:  pkt.Payload[4],
	}
}

// 冻结根因（2026-11）：tgcalls 订阅端只为 SIM[0] 建接收流，其它层 ssrc 被
// libwebrtc 丢弃。改写器必须把选中层输出到 SIM[0] ssrc，切层只在新层关键帧
// 处发生，且序号/时间戳/picture id/TL0PICIDX 跨切层连续。
func TestVideoForwarderSwitchesOnKeyframeWithContinuity(t *testing.T) {
	f := newVideoForwarder(rewriteTestPublisher())
	if f.outSSRC != 1001 || f.outRTX != 1002 {
		t.Fatalf("out ssrc = %d/%d, want SIM[0] 1001 / rtx 1002", f.outSSRC, f.outRTX)
	}
	now := time.Now()

	// 期望层 0：首个非关键帧丢弃并请求关键帧。
	res := f.forward(1001, 0, 0, vp8Packet(t, 1001, 100, 5000, 10, 3, false), now)
	if res.out != nil || res.pliSSRC != 1001 {
		t.Fatalf("non-keyframe before start: out=%v pli=%d, want drop + PLI for 1001", res.out != nil, res.pliSSRC)
	}
	// 层 0 关键帧：开始转发，首层恒等映射。
	res = f.forward(1001, 0, 0, vp8Packet(t, 1001, 101, 6000, 11, 4, true), now)
	if res.out == nil || !res.switched {
		t.Fatalf("layer 0 keyframe must start forwarding")
	}
	if got := parseOut(t, res.out); got != (parsedOut{ssrc: 1001, seq: 101, ts: 6000, pic: 11, tl0: 4}) {
		t.Fatalf("first layer must map 1:1, got %+v", got)
	}
	res = f.forward(1001, 0, 0, vp8Packet(t, 1001, 102, 9000, 12, 5, false), now)
	if got := parseOut(t, res.out); got.seq != 102 || got.pic != 12 {
		t.Fatalf("layer 0 delta frame: %+v", got)
	}

	// 期望升到层 1：先发 PLI；层 1 非关键帧到达前继续转发层 0。
	later := now.Add(100 * time.Millisecond)
	res = f.forward(1003, 1, 1, vp8Packet(t, 1003, 7000, 777000, 500, 90, false), later)
	if res.out != nil || res.pliSSRC != 1003 {
		t.Fatalf("pending switch: out=%v pli=%d, want drop + PLI for 1003", res.out != nil, res.pliSSRC)
	}
	// 等新层关键帧期间旧层继续转发：观看端不出现空窗。
	res = f.forward(1001, 0, 1, vp8Packet(t, 1001, 103, 12000, 13, 6, false), later)
	if res.out == nil {
		t.Fatalf("old layer must keep flowing until the new layer's keyframe arrives")
	}
	if got := parseOut(t, res.out); got.seq != 103 || got.pic != 13 {
		t.Fatalf("old layer during pending switch = %+v", got)
	}

	// 层 1 关键帧：切层，输出仍在 1001 上且各计数连续。
	res = f.forward(1003, 1, 1, vp8Packet(t, 1003, 7001, 780000, 501, 91, true), later)
	if res.out == nil || !res.switched || f.cur != 1 {
		t.Fatalf("layer 1 keyframe must switch: %+v", res)
	}
	got := parseOut(t, res.out)
	if got.ssrc != 1001 || got.seq != 104 || got.pic != 14 || got.tl0 != 7 {
		t.Fatalf("switch output = %+v, want ssrc 1001 seq 104 pic 14 tl0 7", got)
	}
	if int32(got.ts-12000) <= 0 {
		t.Fatalf("timestamp must move forward across the switch: %d -> %d", 12000, got.ts)
	}
	firstTS := got.ts
	res = f.forward(1003, 1, 1, vp8Packet(t, 1003, 7002, 783000, 502, 91, false), later)
	got = parseOut(t, res.out)
	if got.seq != 105 || got.pic != 15 || got.ts != firstTS+3000 {
		t.Fatalf("layer 1 delta frame = %+v, want seq 105 pic 15 ts +3000", got)
	}

	// 切层完成后旧层丢弃。
	if res = f.forward(1001, 0, 1, vp8Packet(t, 1001, 104, 15000, 14, 7, true), later); res.out != nil {
		t.Fatalf("old layer must be dropped after the switch")
	}

	// 层 1 晚到的、早于切层点的包不得转发。
	if res = f.forward(1003, 1, 1, vp8Packet(t, 1003, 7000, 777000, 500, 90, false), later); res.out != nil {
		t.Fatalf("packet older than the switch point must be dropped")
	}
}

// 订阅端 NACK 的是输出序号：必须还原成源层 ssrc + 源序号。RTX 重传必须改写
// 到 SIM[0] 的 RTX ssrc，载荷里的原始序号换算到输出序号空间。
func TestVideoForwarderTranslatesNACKAndRTX(t *testing.T) {
	f := newVideoForwarder(rewriteTestPublisher())
	now := time.Now()
	f.forward(1001, 0, 0, vp8Packet(t, 1001, 100, 5000, 10, 3, true), now)
	f.forward(1003, 1, 1, vp8Packet(t, 1003, 7000, 777000, 500, 90, true), now)
	f.forward(1003, 1, 1, vp8Packet(t, 1003, 7001, 780000, 501, 90, false), now)

	got := f.translateNACK([]uint16{100, 101, 102, 999})
	if len(got[1001]) != 1 || got[1001][0] != 100 {
		t.Fatalf("nack for out seq 100 = %v, want layer 0 seq 100", got[1001])
	}
	if len(got[1003]) != 2 || got[1003][0] != 7000 || got[1003][1] != 7001 {
		t.Fatalf("nack for out seq 101/102 = %v, want layer 1 seq 7000/7001", got[1003])
	}

	inner := vp8Packet(t, 1003, 7001, 780000, 501, 90, false)[12:]
	res := f.forward(1004, 1, 1, rtxPacket(t, 1004, 50, 780000, 7001, inner), now)
	if res.out == nil {
		t.Fatalf("rtx of the current layer must be forwarded")
	}
	var pkt rtp.Packet
	if err := pkt.Unmarshal(res.out); err != nil {
		t.Fatal(err)
	}
	if pkt.SSRC != 1002 {
		t.Fatalf("rtx ssrc = %d, want SIM[0] rtx 1002", pkt.SSRC)
	}
	if osn := binary.BigEndian.Uint16(pkt.Payload); osn != 102 {
		t.Fatalf("rtx original seq = %d, want output seq 102", osn)
	}
	if pic := readVP8PictureID(pkt.Payload[4:]); pic != 12 {
		t.Fatalf("rtx picture id = %d, want rewritten 12", pic)
	}
	// 非当前层的 RTX 丢弃。
	if res = f.forward(1002, 0, 1, rtxPacket(t, 1002, 9, 5000, 100, inner), now); res.out != nil {
		t.Fatalf("rtx of a non-current layer must be dropped")
	}
}

// SR 只转当前层，并改写到输出 ssrc 与时间戳空间。
func TestVideoForwarderTranslatesSenderReport(t *testing.T) {
	f := newVideoForwarder(rewriteTestPublisher())
	now := time.Now()
	f.forward(1001, 0, 0, vp8Packet(t, 1001, 100, 5000, 10, 3, true), now)
	f.forward(1003, 1, 1, vp8Packet(t, 1003, 7000, 777000, 500, 90, true), now.Add(time.Second))

	if sr := f.translateSR(&rtcp.SenderReport{SSRC: 1001, RTPTime: 5000}); sr != nil {
		t.Fatalf("SR of a non-current layer must be dropped")
	}
	sr := f.translateSR(&rtcp.SenderReport{SSRC: 1003, RTPTime: 777000, NTPTime: 42})
	if sr == nil || sr.SSRC != 1001 || sr.NTPTime != 42 {
		t.Fatalf("SR of the current layer = %+v, want ssrc 1001", sr)
	}
	out := parseOut(t, f.forward(1003, 1, 1, vp8Packet(t, 1003, 7001, 777000, 501, 90, false), now.Add(time.Second)).out)
	if sr.RTPTime != out.ts {
		t.Fatalf("SR rtp time %d must match the rewritten media timestamp %d", sr.RTPTime, out.ts)
	}
}

// 订阅端不要视频（maxHeight=0）：全部丢弃；之后恢复时仍需关键帧且序号接续。
func TestVideoForwarderPauseAndResume(t *testing.T) {
	f := newVideoForwarder(rewriteTestPublisher())
	now := time.Now()
	f.forward(1001, 0, 0, vp8Packet(t, 1001, 100, 5000, 10, 3, true), now)
	if res := f.forward(1001, 0, -1, vp8Packet(t, 1001, 101, 8000, 11, 3, true), now); res.out != nil {
		t.Fatalf("maxHeight=0 must drop video")
	}
	res := f.forward(1001, 0, 0, vp8Packet(t, 1001, 102, 11000, 12, 3, false), now)
	if res.out != nil || res.pliSSRC != 1001 {
		t.Fatalf("resume must wait for a keyframe and request one")
	}
	res = f.forward(1001, 0, 0, vp8Packet(t, 1001, 103, 14000, 13, 3, true), now)
	if got := parseOut(t, res.out); got.seq != 101 || got.pic != 11 {
		t.Fatalf("resume output = %+v, want seq 101 pic 11 (continuous)", got)
	}
}
