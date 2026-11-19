package sfu

import (
	"encoding/binary"
	"sync"
	"time"

	"github.com/pion/rtcp"
	"github.com/pion/rtp"
)

// 订阅端只认 SIM[0]：tgcalls 收端按 first_ssrc 建唯一视频接收流（remote_ssrc=
// SIM[0]，rtx_ssrc=其 FID 伙伴），并开启 WebRTC-Video-DiscardPacketsWithUnknownSsrc
// ——其它层 ssrc 的包在 libwebrtc 里直接丢弃。原样转发高层 = 观看端停在最后一帧
// 低层画面（「只有高层冻结」的根因）。videoForwarder 把选中层改写到 SIM[0]
// ssrc 上：序号/时间戳/VP8 picture id 跨切层连续，切层只在新层关键帧处进行。

const (
	// 与下行 payload-types 表一致（convert_phone_group.go：VP8=100/rtx 101）。
	vp8PayloadType    = 100
	vp8RTXPayloadType = 101
	// NACK 反查表容量（输出序号 → 源层 ssrc/序号）。
	nackHistorySize = 2048
	// 待切层迟迟等不到关键帧时重发 PLI 的间隔。
	keyframeRetryInterval = time.Second
	// 切层时时间戳补偿的上限（90kHz，10s）。
	maxTimestampGap = 10 * 90000
)

type seqMapEntry struct {
	valid   bool
	outSeq  uint16
	srcSeq  uint16
	srcSSRC uint32
}

// videoForwarder 是一个订阅端对一个发布端 endpoint 的视频改写状态。
type videoForwarder struct {
	pub     *endpoint
	outSSRC uint32 // SIM[0]
	outRTX  uint32 // SIM[0] 的 FID 伙伴；0 = 无 RTX

	mu      sync.Mutex
	want    int // 最近一次的期望层（-1 = 不要视频）
	lastPLI time.Time
	cur     int // 当前转发层（-1 = 无）
	started bool

	epochSeq uint16 // 当前层首个转发包的源序号（更早的乱序包丢弃）
	seqOff   uint16
	tsOff    uint32
	picOff   uint16
	tl0Off   uint8

	maxSeq     uint16
	maxTS      uint32
	maxPic     uint16
	maxTL0     uint8
	picStarted bool
	tl0Started bool
	lastOut    time.Time

	rtxStarted bool
	rtxSeq     uint16

	hist [nackHistorySize]seqMapEntry
}

func newVideoForwarder(pub *endpoint) *videoForwarder {
	f := &videoForwarder{pub: pub, want: -1, cur: -1}
	if len(pub.plan.layers) > 0 {
		f.outSSRC = pub.plan.layers[0]
		for rtx, media := range pub.plan.rtxOf {
			if media == f.outSSRC {
				f.outRTX = rtx
				break
			}
		}
	}
	return f
}

// forwardResult：out=改写后的包（nil=丢弃）；pliSSRC≠0 时须向发布端请求该层关键帧；
// switched=本包完成切层。
type forwardResult struct {
	out      []byte
	pliSSRC  uint32
	switched bool
}

// forward 处理发布端的一个视频包（媒体或 RTX）。desired 是订阅端当前期望层。
// 期望层变化后继续转发旧层，直到新层关键帧到达才切换（不出现无关键帧的空窗）。
func (f *videoForwarder) forward(ssrc uint32, layer, desired int, raw []byte, now time.Time) (res forwardResult) {
	var hdr rtp.Header
	hlen, err := hdr.Unmarshal(raw)
	if err != nil {
		return res
	}
	end := len(raw)
	if hdr.Padding && end > hlen {
		pad := int(raw[end-1])
		if pad > end-hlen {
			return res
		}
		end -= pad
	}
	_, isRTX := f.pub.plan.rtxOf[ssrc]

	f.mu.Lock()
	defer f.mu.Unlock()

	if desired != f.want {
		f.want = desired
		if desired >= 0 && desired != f.cur && desired < len(f.pub.plan.layers) {
			res.pliSSRC = f.pub.plan.layers[desired]
			f.lastPLI = now
		}
	}
	if desired < 0 {
		f.cur = -1
		return res
	}
	if isRTX {
		res.out = f.rewriteRTX(raw, hlen, end, &hdr, layer)
		return res
	}
	if layer != f.cur {
		if layer != desired {
			return res
		}
		if hdr.PayloadType == vp8PayloadType && !isVP8Keyframe(raw[hlen:end]) {
			if res.pliSSRC == 0 && now.Sub(f.lastPLI) >= keyframeRetryInterval {
				res.pliSSRC = ssrc
				f.lastPLI = now
			}
			return res
		}
		res.switched = true
		f.startEpoch(layer, &hdr, raw[hlen:end], now)
	}
	if int16(hdr.SequenceNumber-f.epochSeq) < 0 {
		return res
	}
	res.out = f.rewriteMedia(raw, hlen, end, &hdr, ssrc, now)
	return res
}

func (f *videoForwarder) startEpoch(layer int, hdr *rtp.Header, payload []byte, now time.Time) {
	var picAt, picLen, tl0At = -1, 0, -1
	if hdr.PayloadType == vp8PayloadType {
		picAt, picLen, tl0At = vp8DescriptorFields(payload)
	}
	if !f.started {
		// 首个层：恒等映射（与原样转发一致）。
		f.seqOff, f.tsOff, f.picOff, f.tl0Off = 0, 0, 0, 0
		f.started = true
	} else {
		f.seqOff = f.maxSeq + 1 - hdr.SequenceNumber
		gap := uint32(now.Sub(f.lastOut) / (time.Second / 90000))
		if gap < 1 {
			gap = 1
		}
		if gap > maxTimestampGap {
			gap = maxTimestampGap
		}
		f.tsOff = f.maxTS + gap - hdr.Timestamp
		if picLen == 2 && f.picStarted {
			f.picOff = (f.maxPic + 1 - readVP8PictureID(payload[picAt:])) & 0x7fff
		}
		if tl0At >= 0 && f.tl0Started {
			f.tl0Off = f.maxTL0 + 1 - payload[tl0At]
		}
	}
	f.cur = layer
	f.epochSeq = hdr.SequenceNumber
}

func (f *videoForwarder) rewriteMedia(raw []byte, hlen, end int, hdr *rtp.Header, ssrc uint32, now time.Time) []byte {
	out := make([]byte, len(raw))
	copy(out, raw)
	outSeq := hdr.SequenceNumber + f.seqOff
	outTS := hdr.Timestamp + f.tsOff
	binary.BigEndian.PutUint16(out[2:4], outSeq)
	binary.BigEndian.PutUint32(out[4:8], outTS)
	binary.BigEndian.PutUint32(out[8:12], f.outSSRC)
	if hdr.PayloadType == vp8PayloadType {
		f.rewriteVP8(out[hlen:end], true)
	}
	if f.lastOut.IsZero() || int16(outSeq-f.maxSeq) > 0 {
		f.maxSeq = outSeq
	}
	if f.lastOut.IsZero() || int32(outTS-f.maxTS) > 0 {
		f.maxTS = outTS
	}
	f.lastOut = now
	f.hist[outSeq%nackHistorySize] = seqMapEntry{valid: true, outSeq: outSeq, srcSeq: hdr.SequenceNumber, srcSSRC: ssrc}
	return out
}

// rewriteRTX：只放行当前层、当前 epoch 内的重传；载荷首 2 字节（原始序号）
// 换算到输出序号空间。纯 padding 的 RTX（发布端带宽探测，SFU 已终结）丢弃。
func (f *videoForwarder) rewriteRTX(raw []byte, hlen, end int, hdr *rtp.Header, layer int) []byte {
	if f.outRTX == 0 || layer != f.cur || end-hlen < 2 {
		return nil
	}
	osn := binary.BigEndian.Uint16(raw[hlen : hlen+2])
	if int16(osn-f.epochSeq) < 0 {
		return nil
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	if !f.rtxStarted {
		f.rtxSeq = hdr.SequenceNumber
		f.rtxStarted = true
	} else {
		f.rtxSeq++
	}
	binary.BigEndian.PutUint16(out[2:4], f.rtxSeq)
	binary.BigEndian.PutUint32(out[4:8], hdr.Timestamp+f.tsOff)
	binary.BigEndian.PutUint32(out[8:12], f.outRTX)
	binary.BigEndian.PutUint16(out[hlen:hlen+2], osn+f.seqOff)
	if hdr.PayloadType == vp8RTXPayloadType {
		f.rewriteVP8(out[hlen+2:end], false)
	}
	return out
}

// rewriteVP8 平移 15 位 picture id 与 TL0PICIDX（libwebrtc 恒用 15 位；
// 7 位 picture id 不改写）。track=false 时（重传）不推进水位。
func (f *videoForwarder) rewriteVP8(p []byte, track bool) {
	picAt, picLen, tl0At := vp8DescriptorFields(p)
	if picLen == 2 {
		pic := (readVP8PictureID(p[picAt:]) + f.picOff) & 0x7fff
		p[picAt] = 0x80 | byte(pic>>8)
		p[picAt+1] = byte(pic)
		if track && (!f.picStarted || ((pic-f.maxPic)&0x7fff) < 0x4000) {
			f.maxPic = pic
			f.picStarted = true
		}
	}
	if tl0At >= 0 {
		tl0 := p[tl0At] + f.tl0Off
		p[tl0At] = tl0
		if track && (!f.tl0Started || int8(tl0-f.maxTL0) >= 0) {
			f.maxTL0 = tl0
			f.tl0Started = true
		}
	}
}

// translateNACK 把订阅端对输出序号的 NACK 还原成 源层 ssrc → 源序号。
func (f *videoForwarder) translateNACK(seqs []uint16) map[uint32][]uint16 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[uint32][]uint16)
	for _, s := range seqs {
		e := f.hist[s%nackHistorySize]
		if e.valid && e.outSeq == s {
			out[e.srcSSRC] = append(out[e.srcSSRC], e.srcSeq)
		}
	}
	return out
}

// keyframeSSRC 返回订阅端 PLI 应转投的源层 ssrc：待切层优先（拿到其关键帧
// 即完成切换），否则当前层。0 = 无。
func (f *videoForwarder) keyframeSSRC() uint32 {
	f.mu.Lock()
	defer f.mu.Unlock()
	layer := f.want
	if layer < 0 {
		layer = f.cur
	}
	if layer < 0 || layer >= len(f.pub.plan.layers) {
		return 0
	}
	return f.pub.plan.layers[layer]
}

// translateSR 只转当前层的 SR，并改写到输出 ssrc/时间戳空间（A/V 同步用
// NTP↔RTP 映射；转发别层的 SR 会给出错误映射）。nil = 不转发。
func (f *videoForwarder) translateSR(sr *rtcp.SenderReport) *rtcp.SenderReport {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.started || f.cur < 0 || f.cur >= len(f.pub.plan.layers) || sr.SSRC != f.pub.plan.layers[f.cur] {
		return nil
	}
	return &rtcp.SenderReport{
		SSRC:        f.outSSRC,
		NTPTime:     sr.NTPTime,
		RTPTime:     sr.RTPTime + f.tsOff,
		PacketCount: sr.PacketCount,
		OctetCount:  sr.OctetCount,
	}
}

// isVP8Keyframe 跳过 VP8 payload descriptor 后读帧标签首字节 bit0（0=关键帧）。
// 仅对媒体 ssrc 调用（RTX 载荷前还有 2 字节原始序号，不适用）。
func isVP8Keyframe(p []byte) bool {
	if len(p) < 2 {
		return false
	}
	b0 := p[0]
	if b0&0x10 == 0 || b0&0x07 != 0 { // 须为 partition 0 起始（S=1, PID=0）
		return false
	}
	n := 1
	if b0&0x80 != 0 { // X 扩展位
		if len(p) < n+1 {
			return false
		}
		x := p[n]
		n++
		if x&0x80 != 0 { // I: picture id
			if len(p) < n+1 {
				return false
			}
			if p[n]&0x80 != 0 {
				n += 2
			} else {
				n++
			}
		}
		if x&0x40 != 0 { // L: TL0 index
			n++
		}
		if x&0x30 != 0 { // T/K: temporal/scalability
			n++
		}
	}
	if len(p) < n+1 {
		return false
	}
	return p[n]&0x01 == 0
}

// vp8DescriptorFields 返回 VP8 payload descriptor 中 picture id 的位置与长度
// （picLen：0=无，1=7 位，2=15 位）和 TL0PICIDX 的位置（-1=无）。
func vp8DescriptorFields(p []byte) (picAt, picLen, tl0At int) {
	picAt, tl0At = -1, -1
	if len(p) < 2 || p[0]&0x80 == 0 {
		return picAt, 0, tl0At
	}
	x := p[1]
	n := 2
	if x&0x80 != 0 {
		if len(p) < n+1 {
			return -1, 0, -1
		}
		if p[n]&0x80 != 0 {
			if len(p) < n+2 {
				return -1, 0, -1
			}
			picAt, picLen = n, 2
			n += 2
		} else {
			picAt, picLen = n, 1
			n++
		}
	}
	if x&0x40 != 0 {
		if len(p) < n+1 {
			return -1, 0, -1
		}
		tl0At = n
	}
	return picAt, picLen, tl0At
}

func readVP8PictureID(p []byte) uint16 {
	return uint16(p[0]&0x7f)<<8 | uint16(p[1])
}
