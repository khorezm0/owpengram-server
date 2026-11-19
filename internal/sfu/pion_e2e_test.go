package sfu

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sctp"
	"github.com/pion/srtp/v3"
	"go.uber.org/zap/zaptest"
)

var errClientDTLSStateMissing = errors.New("client dtls state missing")

// fakeTgcallsClient 按 tgcalls GroupNetworkManager 的角色契约模拟客户端：
// ICE CONTROLLED（等待 SFU 发起连通性检查）、DTLS setup="passive"（server 角色，
// 等 SFU 主动握手）、SRTP isClient=false。
type fakeTgcallsClient struct {
	t           *testing.T
	ufrag, pwd  string
	cert        tls.Certificate
	fingerprint string
	ssrc        uint32
	groups      []SsrcGroup

	dtls    *dtls.Conn // data channel（SCTP over DTLS）复用同一条 DTLS
	session *srtp.SessionSRTP
	write   *srtp.WriteStreamSRTP
	// SRTCP：发带宽反馈（TWCC/REMB）/ 收 SFU 回投的反馈。
	rtcpSession *srtp.SessionSRTCP
	rtcpWrite   *srtp.WriteStreamSRTCP
	closeFn     []func()
}

func newFakeTgcallsClient(t *testing.T, ssrc uint32) *fakeTgcallsClient {
	t.Helper()
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		t.Fatalf("client cert: %v", err)
	}
	fp, err := certificateFingerprint(cert.Certificate[0])
	if err != nil {
		t.Fatalf("client fingerprint: %v", err)
	}
	ufrag, _ := randomICEString(8)
	pwd, _ := randomICEString(24)
	return &fakeTgcallsClient{t: t, ufrag: ufrag, pwd: pwd, cert: cert, fingerprint: fp, ssrc: ssrc}
}

func (c *fakeTgcallsClient) offer() ClientOffer {
	return ClientOffer{
		AudioSSRC:         c.ssrc,
		Ufrag:             c.ufrag,
		Pwd:               c.pwd,
		FingerprintSHA256: c.fingerprint,
		SsrcGroups:        c.groups,
	}
}

// connect 完成 ICE(controlled)+DTLS(server)+SRTP 建链。
func (c *fakeTgcallsClient) connect(ctx context.Context, answer ServerAnswer) error {
	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:    []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:  []ice.CandidateType{ice.CandidateTypeHost},
		LocalUfrag:      c.ufrag,
		LocalPwd:        c.pwd,
		IncludeLoopback: true,
	})
	if err != nil {
		return err
	}
	c.closeFn = append(c.closeFn, func() { _ = agent.Close() })
	if err := agent.OnCandidate(func(ice.Candidate) {}); err != nil {
		return err
	}
	if err := agent.GatherCandidates(); err != nil {
		return err
	}
	for _, cand := range answer.Candidates {
		remote, err := ice.NewCandidateHost(&ice.CandidateHostConfig{
			Network:   "udp",
			Address:   cand.IP,
			Port:      cand.Port,
			Component: 1,
		})
		if err != nil {
			return err
		}
		if err := agent.AddRemoteCandidate(remote); err != nil {
			return err
		}
	}
	conn, err := agent.Accept(ctx, answer.Ufrag, answer.Pwd) // CONTROLLED
	if err != nil {
		return err
	}
	demux := newDemuxer(conn)
	c.closeFn = append(c.closeFn, demux.Close)
	dtlsRaw := demux.dtlsConn()
	dtlsConn, err := dtls.Server(dtlsnet.PacketConnFromConn(dtlsRaw), dtlsRaw.RemoteAddr(), &dtls.Config{
		Certificates:         []tls.Certificate{c.cert},
		ClientAuth:           dtls.RequireAnyClientCert,
		InsecureSkipVerify:   true,
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AEAD_AES_128_GCM,
			dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
	})
	if err != nil {
		return err
	}
	c.dtls = dtlsConn
	hsCtx, hsCancel := context.WithTimeout(ctx, 20*time.Second)
	err = dtlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		return err
	}
	state, ok := dtlsConn.ConnectionState()
	if !ok {
		return errClientDTLSStateMissing
	}
	// 服务端证书指纹应等于信令面下发的 answer.FingerprintSHA256。
	gotFP, err := certificateFingerprint(state.PeerCertificates[0])
	if err != nil || normalizeFingerprint(gotFP) != normalizeFingerprint(answer.FingerprintSHA256) {
		return fmt.Errorf("sfu fingerprint mismatch: %v / %s vs %s", err, gotFP, answer.FingerprintSHA256)
	}
	profile, _ := dtlsConn.SelectedSRTPProtectionProfile()
	srtpConfig := &srtp.Config{}
	switch profile {
	case dtls.SRTP_AEAD_AES_128_GCM:
		srtpConfig.Profile = srtp.ProtectionProfileAeadAes128Gcm
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		srtpConfig.Profile = srtp.ProtectionProfileAes128CmHmacSha1_80
	default:
		return fmt.Errorf("unexpected srtp profile %v", profile)
	}
	if err := srtpConfig.ExtractSessionKeysFromDTLS(&state, false); err != nil {
		return err
	}
	c.session, err = srtp.NewSessionSRTP(demux.srtpConn(), srtpConfig)
	if err != nil {
		return err
	}
	c.write, err = c.session.OpenWriteStream()
	if err != nil {
		return err
	}
	c.rtcpSession, err = srtp.NewSessionSRTCP(demux.srtcpConn(), srtpConfig)
	if err != nil {
		return err
	}
	c.rtcpWrite, err = c.rtcpSession.OpenWriteStream()
	return err
}

// sendRTCPFeedback 向 SFU 发一条 RTCP（订阅端带宽反馈）。
func (c *fakeTgcallsClient) sendRTCPFeedback(pkt rtcp.Packet) error {
	raw, err := rtcp.Marshal([]rtcp.Packet{pkt})
	if err != nil {
		return err
	}
	_, err = c.rtcpWrite.Write(raw)
	return err
}

// readRTCP 读 SFU 回投到本端的第一条 RTCP。
func (c *fakeTgcallsClient) readRTCP() (rtcp.Packet, error) {
	stream, _, err := c.rtcpSession.AcceptStream()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 1500)
	n, err := stream.Read(buf)
	if err != nil {
		return nil, err
	}
	pkts, err := rtcp.Unmarshal(buf[:n])
	if err != nil || len(pkts) == 0 {
		if err == nil {
			err = fmt.Errorf("empty rtcp compound")
		}
		return nil, err
	}
	return pkts[0], nil
}

func (c *fakeTgcallsClient) close() {
	for i := len(c.closeFn) - 1; i >= 0; i-- {
		c.closeFn[i]()
	}
}

// openDataChannel 以 SCTP client 角色建关联并 DCEP OPEN 一条 "data" 通道
// （与 tweb/tgcalls 同路径：SFU 侧 sctp.Server + datachannel.Accept）。
func (c *fakeTgcallsClient) openDataChannel(ctx context.Context) (*datachannel.DataChannel, error) {
	logf := logging.NewDefaultLoggerFactory()
	logf.DefaultLogLevel = logging.LogLevelError
	assoc, err := sctp.Client(sctp.Config{NetConn: c.dtls, LoggerFactory: logf})
	if err != nil {
		return nil, err
	}
	c.closeFn = append(c.closeFn, func() { _ = assoc.Close() })
	dc, err := datachannel.Dial(assoc, 0, &datachannel.Config{
		ChannelType:   datachannel.ChannelTypeReliable,
		Label:         "data",
		LoggerFactory: logf,
	})
	if err != nil {
		return nil, err
	}
	return dc, nil
}

// sendReceiverVideoConstraints 发一条 tweb streamManager 同形的订阅意愿消息。
func (c *fakeTgcallsClient) sendReceiverVideoConstraints(dc *datachannel.DataChannel, endpointID string, minHeight, maxHeight int) error {
	msg := map[string]any{
		"colibriClass":       "ReceiverVideoConstraints",
		"constraints":        map[string]any{endpointID: map[string]any{"minHeight": minHeight, "maxHeight": maxHeight}},
		"defaultConstraints": map[string]any{"maxHeight": 0},
		"onStageEndpoints":   []string{},
	}
	raw, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	_, err = dc.WriteDataChannel(raw, true)
	return err
}

// sendOpusPacket 构造带 audio-level 扩展（one-byte header，id=1）的 RTP 包。
func (c *fakeTgcallsClient) sendOpusPacket(seq uint16, payload []byte, audioLevel byte) error {
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    111, // opus
			SequenceNumber: seq,
			Timestamp:      uint32(seq) * 960,
			SSRC:           c.ssrc,
		},
		Payload: payload,
	}
	pkt.Header.Extension = true
	pkt.Header.ExtensionProfile = 0xBEDE
	if err := pkt.Header.SetExtension(1, []byte{audioLevel}); err != nil {
		return err
	}
	raw, err := pkt.Marshal()
	if err != nil {
		return err
	}
	_, err = c.write.Write(raw)
	return err
}

// sendVideoPacket 构造指定 ssrc 的视频 RTP 包（VP8 PT=100）。载荷第 3 字节
// 是 VP8 帧头（seq 偶数 = 关键帧），第 4 字节是源 ssrc 标记：SFU 把所有层改写
// 到 SIM[0] 上，订阅端只能靠这个标记分辨收到的是哪一层。
func (c *fakeTgcallsClient) sendVideoPacket(ssrc uint32, seq uint16) error {
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    100, // VP8
			SequenceNumber: seq,
			Timestamp:      uint32(seq) * 3000,
			SSRC:           ssrc,
		},
		Payload: []byte{0x90, 0x00, byte(seq), byte(ssrc)},
	}
	raw, err := pkt.Marshal()
	if err != nil {
		return err
	}
	_, err = c.write.Write(raw)
	return err
}

// sendVideoPacketTWCC 构造带 transport-wide-cc 扩展（id=3）的视频 RTP 包，
// 模拟发布端真实的传输层序号（SFU 的 TWCC 终结器据此生成反馈）。
func (c *fakeTgcallsClient) sendVideoPacketTWCC(ssrc uint32, seq, twccSeq uint16) error {
	pkt := &rtp.Packet{
		Header: rtp.Header{
			Version:        2,
			PayloadType:    100, // VP8
			SequenceNumber: seq,
			Timestamp:      uint32(seq) * 3000,
			SSRC:           ssrc,
		},
		Payload: []byte{0x90, 0x00, byte(seq)},
	}
	pkt.Header.Extension = true
	pkt.Header.ExtensionProfile = 0xBEDE
	if err := pkt.Header.SetExtension(3, []byte{byte(twccSeq >> 8), byte(twccSeq)}); err != nil {
		return err
	}
	raw, err := pkt.Marshal()
	if err != nil {
		return err
	}
	_, err = c.write.Write(raw)
	return err
}

// 视频选层（无订阅意愿的缺省行为）：发布端三层 simulcast，订阅端不发
// ReceiverVideoConstraints 时退回 v1 行为——只收 SIM[0]（订阅端只为该 ssrc 建
// 解码 sink，高层包客户端会丢弃，SFU 侧不转发省下行）。
func TestPionSFUForwardsOnlyBaseSimulcastLayer(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e sfu test")
	}
	port := pickUDPPort(t)
	svc, err := NewPion(PionConfig{UDPPort: port, AdvertiseIP: "127.0.0.1", Logger: zaptest.NewLogger(t)})
	if err != nil {
		t.Fatalf("new pion sfu: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callID = int64(901)
	alice := newFakeTgcallsClient(t, 0x500)
	base := alice.ssrc + 1
	alice.groups = []SsrcGroup{
		{Semantics: "SIM", Sources: []uint32{base, base + 2, base + 4}},
		{Semantics: "FID", Sources: []uint32{base, base + 1}},
		{Semantics: "FID", Sources: []uint32{base + 2, base + 3}},
		{Semantics: "FID", Sources: []uint32{base + 4, base + 5}},
	}
	bob := newFakeTgcallsClient(t, 0x600)
	defer alice.close()
	defer bob.close()

	answerA, err := svc.Join(ctx, callID, 1, EndpointMain, alice.offer())
	if err != nil {
		t.Fatalf("join alice: %v", err)
	}
	answerB, err := svc.Join(ctx, callID, 2, EndpointMain, bob.offer())
	if err != nil {
		t.Fatalf("join bob: %v", err)
	}
	errCh := make(chan error, 2)
	go func() { errCh <- alice.connect(ctx, answerA) }()
	go func() { errCh <- bob.connect(ctx, answerB) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client connect: %v", err)
		}
	}

	// alice 同时在 layer0（应转发）与 layer1（应被 SFU 终结）发包。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		seq := uint16(1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = alice.sendVideoPacket(base, seq)
				_ = alice.sendVideoPacket(base+2, seq)
				seq++
			}
		}
	}()

	// bob 只能收到 layer0 的内容（载荷标记 base），且在 SIM[0] ssrc 上；观察窗口
	// 内绝不能出现 layer1 的内容。SFU 把各层都改写到 SIM[0]，只看 ssrc 分辨不出层。
	type videoPkt struct {
		ssrc   uint32
		marker byte
	}
	got := make(chan videoPkt, 256)
	go func() {
		for {
			stream, _, err := bob.session.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1500)
				for {
					n, err := stream.Read(buf)
					if err != nil {
						return
					}
					var pkt rtp.Packet
					if pkt.Unmarshal(buf[:n]) != nil || len(pkt.Payload) < 4 {
						continue
					}
					select {
					case got <- videoPkt{ssrc: pkt.SSRC, marker: pkt.Payload[3]}:
					default:
					}
				}
			}()
		}
	}()
	check := func(p videoPkt) {
		if p.ssrc != base || p.marker != byte(base) {
			t.Fatalf("bob received ssrc %#x marker %#x, want only layer 0 (%#x) on SIM[0]", p.ssrc, p.marker, byte(base))
		}
	}
	select {
	case p := <-got:
		check(p)
	case <-time.After(10 * time.Second):
		t.Fatalf("bob never received base layer stream")
	}
	// 再观察一段时间确认高层不漏。
	quiet := time.After(2 * time.Second)
	for {
		select {
		case p := <-got:
			check(p)
		case <-quiet:
			_ = svc.CloseRoom(ctx, callID)
			return
		}
	}
}

// 订阅端选层：bob 置顶请求（maxHeight=720）→ 只收顶层；carol 不要视频
// （maxHeight=0）→ 不收任何视频层。验证 ReceiverVideoConstraints 端到端生效。
func TestPionSFUSelectsLayerPerSubscriber(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e sfu test")
	}
	port := pickUDPPort(t)
	svc, err := NewPion(PionConfig{UDPPort: port, AdvertiseIP: "127.0.0.1", Logger: zaptest.NewLogger(t)})
	if err != nil {
		t.Fatalf("new pion sfu: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callID = int64(902)
	alice := newFakeTgcallsClient(t, 0x500)
	base := alice.ssrc + 1
	alice.groups = []SsrcGroup{
		{Semantics: "SIM", Sources: []uint32{base, base + 2, base + 4}},
		{Semantics: "FID", Sources: []uint32{base, base + 1}},
		{Semantics: "FID", Sources: []uint32{base + 2, base + 3}},
		{Semantics: "FID", Sources: []uint32{base + 4, base + 5}},
	}
	bob := newFakeTgcallsClient(t, 0x600)
	carol := newFakeTgcallsClient(t, 0x700)
	defer alice.close()
	defer bob.close()
	defer carol.close()

	answerA, err := svc.Join(ctx, callID, 1, EndpointMain, alice.offer())
	if err != nil {
		t.Fatalf("join alice: %v", err)
	}
	answerB, err := svc.Join(ctx, callID, 2, EndpointMain, bob.offer())
	if err != nil {
		t.Fatalf("join bob: %v", err)
	}
	answerC, err := svc.Join(ctx, callID, 3, EndpointMain, carol.offer())
	if err != nil {
		t.Fatalf("join carol: %v", err)
	}
	errCh := make(chan error, 3)
	go func() { errCh <- alice.connect(ctx, answerA) }()
	go func() { errCh <- bob.connect(ctx, answerB) }()
	go func() { errCh <- carol.connect(ctx, answerC) }()
	for i := 0; i < 3; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client connect: %v", err)
		}
	}

	// bob 置顶 alice（720 → 顶层）；carol 不要 alice 的视频（0 → 全断）。
	dcB, err := bob.openDataChannel(ctx)
	if err != nil {
		t.Fatalf("bob data channel: %v", err)
	}
	defer dcB.Close()
	if err := bob.sendReceiverVideoConstraints(dcB, fmt.Sprintf("audio-%d", alice.ssrc), 180, 720); err != nil {
		t.Fatalf("bob send constraints: %v", err)
	}
	dcC, err := carol.openDataChannel(ctx)
	if err != nil {
		t.Fatalf("carol data channel: %v", err)
	}
	defer dcC.Close()
	if err := carol.sendReceiverVideoConstraints(dcC, fmt.Sprintf("audio-%d", alice.ssrc), 0, 0); err != nil {
		t.Fatalf("carol send constraints: %v", err)
	}
	// 约束经 SCTP 异步落地，留出传播窗口。
	time.Sleep(500 * time.Millisecond)

	// alice 三层同时发。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		seq := uint16(1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = alice.sendVideoPacket(base, seq)
				_ = alice.sendVideoPacket(base+2, seq)
				_ = alice.sendVideoPacket(base+4, seq)
				seq++
			}
		}
	}()

	// bob 只收顶层内容（标记 base+4），且一律在 SIM[0] ssrc（base）上——
	// 订阅端只为 SIM[0] 建接收流，其它 ssrc 被 libwebrtc 丢弃。顶层首包前的
	// 低层是合法瞬态（宁低勿断流的回退）。carol 一条视频都不能收。
	type videoPkt struct {
		ssrc   uint32
		marker byte
	}
	bobVideo := make(chan videoPkt, 256)
	carolVideo := make(chan uint32, 8)
	go func() {
		for ssrc := range carolVideo {
			t.Errorf("carol received video ssrc %#x despite maxHeight=0", ssrc)
		}
	}()
	go func() {
		for {
			_, ssrc, err := carol.session.AcceptStream()
			if err != nil {
				return
			}
			carolVideo <- ssrc
		}
	}()
	go func() {
		for {
			stream, _, err := bob.session.AcceptStream()
			if err != nil {
				return
			}
			go func() {
				buf := make([]byte, 1500)
				for {
					n, err := stream.Read(buf)
					if err != nil {
						return
					}
					var pkt rtp.Packet
					if pkt.Unmarshal(buf[:n]) != nil || len(pkt.Payload) < 4 {
						continue
					}
					select {
					case bobVideo <- videoPkt{ssrc: pkt.SSRC, marker: pkt.Payload[3]}:
					default:
					}
				}
			}()
		}
	}()
	deadline := time.After(10 * time.Second)
	sawTop := false
	for !sawTop {
		select {
		case p := <-bobVideo:
			if p.ssrc != base {
				t.Fatalf("bob received video on ssrc %#x, want everything rewritten to SIM[0] %#x", p.ssrc, base)
			}
			sawTop = p.marker == byte(base+4)
		case <-deadline:
			t.Fatalf("bob never received the requested top layer")
		}
	}
	quiet := time.After(2 * time.Second)
	for {
		select {
		case p := <-bobVideo:
			if p.ssrc != base || p.marker != byte(base+4) {
				t.Fatalf("bob received ssrc %#x marker %#x after the top layer started, want only top layer on %#x", p.ssrc, p.marker, base)
			}
		case <-quiet:
			_ = svc.CloseRoom(ctx, callID)
			return
		}
	}
}

func TestPionSFUForwardsOpusBetweenClients(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e sfu test")
	}
	port := pickUDPPort(t)
	svc, err := NewPion(PionConfig{
		UDPPort:     port,
		AdvertiseIP: "127.0.0.1",
		Logger:      zaptest.NewLogger(t),
	})
	if err != nil {
		t.Fatalf("new pion sfu: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callID = int64(900)
	alice := newFakeTgcallsClient(t, 0xA11CE)
	bob := newFakeTgcallsClient(t, 0xB0B)
	defer alice.close()
	defer bob.close()

	answerA, err := svc.Join(ctx, callID, 1, EndpointMain, alice.offer())
	if err != nil {
		t.Fatalf("join alice: %v", err)
	}
	if len(answerA.Candidates) != 1 || answerA.Candidates[0].Port != port {
		t.Fatalf("answer candidates = %+v", answerA.Candidates)
	}
	answerB, err := svc.Join(ctx, callID, 2, EndpointMain, bob.offer())
	if err != nil {
		t.Fatalf("join bob: %v", err)
	}
	// 两端建链（ICE prflx → DTLS 由 SFU 主动握手 → SRTP）。
	errCh := make(chan error, 2)
	go func() { errCh <- alice.connect(ctx, answerA) }()
	go func() { errCh <- bob.connect(ctx, answerB) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client connect: %v", err)
		}
	}

	// alice 持续发包（SFU AcceptStream 在首包后建立读流）。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		seq := uint16(1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = alice.sendOpusPacket(seq, []byte{0xDE, 0xAD, byte(seq)}, 0x7F)
				seq++
			}
		}
	}()

	// bob 收到来自 alice 的转发流：SSRC 不重写、扩展保留。
	acceptCtx, acceptCancel := context.WithTimeout(ctx, 15*time.Second)
	defer acceptCancel()
	type accepted struct {
		stream *srtp.ReadStreamSRTP
		ssrc   uint32
	}
	got := make(chan accepted, 1)
	go func() {
		stream, ssrc, err := bob.session.AcceptStream()
		if err == nil {
			got <- accepted{stream, ssrc}
		}
	}()
	var inbound accepted
	select {
	case inbound = <-got:
	case <-acceptCtx.Done():
		t.Fatalf("bob never received forwarded stream")
	}
	if inbound.ssrc != alice.ssrc {
		t.Fatalf("forwarded ssrc = %#x, want alice %#x（SFU 不得重写 SSRC）", inbound.ssrc, alice.ssrc)
	}
	buf := make([]byte, 1500)
	n, err := inbound.stream.Read(buf)
	if err != nil {
		t.Fatalf("bob read: %v", err)
	}
	var pkt rtp.Packet
	if err := pkt.Unmarshal(buf[:n]); err != nil {
		t.Fatalf("unmarshal forwarded packet: %v", err)
	}
	if pkt.PayloadType != 111 || pkt.SSRC != alice.ssrc {
		t.Fatalf("forwarded packet = %+v", pkt.Header)
	}
	if ext := pkt.Header.GetExtension(1); len(ext) != 1 || ext[0] != 0x7F {
		t.Fatalf("audio-level extension lost: %v（speaking 指示依赖逐包透传）", ext)
	}

	// 媒体面活性：双端都应在 alive 集合（alice 发包、bob 收包均计活性…bob 仅收不发，
	// 其活性来自 SFU 写出？写出不计；bob 至少 connected+握手活性在窗口内）。
	alive := svc.AliveUserIDs(callID)
	aliveSet := map[int64]bool{}
	for _, id := range alive {
		aliveSet[id] = true
	}
	if !aliveSet[1] {
		t.Fatalf("alice must be media-alive, got %v", alive)
	}

	if err := svc.Leave(ctx, callID, 1, EndpointMain); err != nil {
		t.Fatalf("leave: %v", err)
	}
	if err := svc.CloseRoom(ctx, callID); err != nil {
		t.Fatalf("close room: %v", err)
	}
}

func pickUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("pick port: %v", err)
	}
	port := conn.LocalAddr().(*net.UDPAddr).Port
	_ = conn.Close()
	return port
}

// 实况回归（2026-11 屏幕共享黑屏）：发布端两层 SIM 只编层 0，订阅端请求
// 360（映射层 1）。严格 layer==target 把唯一在发的层 0 也裁掉 → 黑屏；
// 宁低勿断流回退后订阅端必须收到层 0。
func TestPionSFUScreencastFallsBackToLowLayer(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e sfu test")
	}
	port := pickUDPPort(t)
	svc, err := NewPion(PionConfig{UDPPort: port, AdvertiseIP: "127.0.0.1", Logger: zaptest.NewLogger(t)})
	if err != nil {
		t.Fatalf("new pion sfu: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callID = int64(903)
	alice := newFakeTgcallsClient(t, 0x800)
	base := alice.ssrc + 1
	// 屏幕共享同款：SIM 两层 + 每层 FID。
	alice.groups = []SsrcGroup{
		{Semantics: "SIM", Sources: []uint32{base, base + 2}},
		{Semantics: "FID", Sources: []uint32{base, base + 1}},
		{Semantics: "FID", Sources: []uint32{base + 2, base + 3}},
	}
	bob := newFakeTgcallsClient(t, 0x900)
	defer alice.close()
	defer bob.close()

	answerA, err := svc.Join(ctx, callID, 1, EndpointMain, alice.offer())
	if err != nil {
		t.Fatalf("join alice: %v", err)
	}
	answerB, err := svc.Join(ctx, callID, 2, EndpointMain, bob.offer())
	if err != nil {
		t.Fatalf("join bob: %v", err)
	}
	errCh := make(chan error, 2)
	go func() { errCh <- alice.connect(ctx, answerA) }()
	go func() { errCh <- bob.connect(ctx, answerB) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client connect: %v", err)
		}
	}

	// bob 请求 360 → 层 1（严格选层的目标）。
	dcB, err := bob.openDataChannel(ctx)
	if err != nil {
		t.Fatalf("bob data channel: %v", err)
	}
	defer dcB.Close()
	if err := bob.sendReceiverVideoConstraints(dcB, fmt.Sprintf("audio-%d", alice.ssrc), 180, 360); err != nil {
		t.Fatalf("bob send constraints: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// alice 只发层 0（实况：第二编码层从不发包）。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		seq := uint16(1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = alice.sendVideoPacket(base, seq)
				seq++
			}
		}
	}()

	// bob 必须收到层 0——而不是黑屏。
	bobVideo := make(chan uint32, 8)
	go func() {
		for {
			stream, ssrc, err := bob.session.AcceptStream()
			if err != nil {
				return
			}
			if ssrc != bob.ssrc {
				bobVideo <- ssrc
			}
			go func() {
				buf := make([]byte, 1500)
				for {
					if _, err := stream.Read(buf); err != nil {
						return
					}
				}
			}()
		}
	}()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case ssrc := <-bobVideo:
			if ssrc != base {
				t.Fatalf("bob received ssrc %#x, want the only active layer %#x", ssrc, base)
			}
			_ = svc.CloseRoom(ctx, callID)
			return
		case <-deadline:
			t.Fatalf("bob never received the fallback layer %#x", base)
		}
	}
}

// transport-cc 终结（2026-11 屏幕共享升 720p 黑屏回落 360p 的根因）：订阅端
// 只收到被选层裁剪后的流，其 transport-cc/REMB 把 SFU 故意丢的层报成丢包、
// 把低层码率当成带宽上限——回投会压垮发布端带宽估计。SFU 必须丢弃订阅端的
// 带宽反馈，改按自己收到的发布端 RTP（全部层、序号连续）自产 transport-cc
// 回投，发布端据此升码率、编高层。
func TestPionSFUTerminatesTransportCC(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e sfu test")
	}
	port := pickUDPPort(t)
	svc, err := NewPion(PionConfig{UDPPort: port, AdvertiseIP: "127.0.0.1", Logger: zaptest.NewLogger(t)})
	if err != nil {
		t.Fatalf("new pion sfu: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callID = int64(904)
	alice := newFakeTgcallsClient(t, 0xa00)
	base := alice.ssrc + 1
	alice.groups = []SsrcGroup{
		{Semantics: "SIM", Sources: []uint32{base, base + 2}},
		{Semantics: "FID", Sources: []uint32{base, base + 1}},
		{Semantics: "FID", Sources: []uint32{base + 2, base + 3}},
	}
	bob := newFakeTgcallsClient(t, 0xb00)
	defer alice.close()
	defer bob.close()

	answerA, err := svc.Join(ctx, callID, 1, EndpointMain, alice.offer())
	if err != nil {
		t.Fatalf("join alice: %v", err)
	}
	answerB, err := svc.Join(ctx, callID, 2, EndpointMain, bob.offer())
	if err != nil {
		t.Fatalf("join bob: %v", err)
	}
	errCh := make(chan error, 2)
	go func() { errCh <- alice.connect(ctx, answerA) }()
	go func() { errCh <- bob.connect(ctx, answerB) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client connect: %v", err)
		}
	}

	// alice（发布端）持续发带传输层序号的视频包，序号从 1 递增。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		seq, twccSeq := uint16(1), uint16(1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = alice.sendVideoPacketTWCC(base, seq, twccSeq)
				seq++
				twccSeq++
			}
		}
	}()

	// bob（订阅端）发 REMB 与 transport-cc：描述的是被裁剪后的 SFU→bob 流，
	// SFU 必须丢弃，绝不能回投 alice。
	if err := bob.sendRTCPFeedback(&rtcp.ReceiverEstimatedMaximumBitrate{
		Bitrate: 1000000,
		SSRCs:   []uint32{base},
	}); err != nil {
		t.Fatalf("bob send remb: %v", err)
	}
	twcc := &rtcp.TransportLayerCC{
		Header:     rtcp.Header{Type: rtcp.TypeTransportSpecificFeedback, Count: rtcp.FormatTCC},
		SenderSSRC: bob.ssrc,
		MediaSSRC:  base,
	}
	twcc.Header.Length = twcc.Len()/4 - 1
	if err := bob.sendRTCPFeedback(twcc); err != nil {
		t.Fatalf("bob send twcc: %v", err)
	}

	rtcpCh := make(chan rtcp.Packet, 16)
	go func() {
		for {
			stream, _, err := alice.rtcpSession.AcceptStream()
			if err != nil {
				return
			}
			go func(stream *srtp.ReadStreamSRTCP) {
				buf := make([]byte, 1500)
				for {
					n, err := stream.Read(buf)
					if err != nil {
						return
					}
					pkts, err := rtcp.Unmarshal(buf[:n])
					if err != nil {
						continue
					}
					for _, pkt := range pkts {
						rtcpCh <- pkt
					}
				}
			}(stream)
		}
	}()

	// 收集 alice 收到的 RTCP：必须出现 SFU 自产的 transport-cc（覆盖 alice
	// 发的序号），且绝不能出现 bob 的 REMB。
	var firstTWCC *rtcp.TransportLayerCC
	rembCount := 0
	deadline := time.After(2 * time.Second)
collect:
	for {
		select {
		case pkt := <-rtcpCh:
			switch fb := pkt.(type) {
			case *rtcp.TransportLayerCC:
				if firstTWCC == nil && fb.PacketStatusCount > 0 {
					firstTWCC = fb
				}
			case *rtcp.ReceiverEstimatedMaximumBitrate:
				rembCount++
			}
		case <-deadline:
			break collect
		}
	}
	if firstTWCC == nil {
		t.Fatalf("publisher never received SFU-generated transport-cc feedback")
	}
	if rembCount != 0 {
		t.Fatalf("viewer REMB relayed to publisher %d times; SFU must terminate bandwidth feedback", rembCount)
	}
	if firstTWCC.SenderSSRC == bob.ssrc {
		t.Fatalf("publisher received the viewer's own twcc (sender ssrc %#x); it must not be relayed", bob.ssrc)
	}
	if firstTWCC.MediaSSRC != base {
		t.Fatalf("generated twcc media ssrc = %d, want %d", firstTWCC.MediaSSRC, base)
	}
	if firstTWCC.BaseSequenceNumber != 1 {
		t.Fatalf("generated twcc base seq = %d, want 1 (alice's first transport-wide seq)", firstTWCC.BaseSequenceNumber)
	}
	if len(firstTWCC.RecvDeltas) == 0 {
		t.Fatalf("generated twcc reports no received packets: %+v", firstTWCC)
	}
	_ = svc.CloseRoom(ctx, callID)
}

// 切层关键帧请求（2026-11 「pin 升高清即冻结」根因）：订阅端升层后 SFU 改转
// 新层 ssrc，必须主动向发布端要新层关键帧，否则观看端解码器拿不到关键帧
// 即冻结（只有高层冻、低层正常）。
func TestPionSFURequestsKeyframeOnLayerSwitch(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e sfu test")
	}
	port := pickUDPPort(t)
	svc, err := NewPion(PionConfig{UDPPort: port, AdvertiseIP: "127.0.0.1", Logger: zaptest.NewLogger(t)})
	if err != nil {
		t.Fatalf("new pion sfu: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const callID = int64(905)
	alice := newFakeTgcallsClient(t, 0xc00)
	base := alice.ssrc + 1
	alice.groups = []SsrcGroup{
		{Semantics: "SIM", Sources: []uint32{base, base + 2, base + 4}},
		{Semantics: "FID", Sources: []uint32{base, base + 1}},
		{Semantics: "FID", Sources: []uint32{base + 2, base + 3}},
		{Semantics: "FID", Sources: []uint32{base + 4, base + 5}},
	}
	bob := newFakeTgcallsClient(t, 0xd00)
	defer alice.close()
	defer bob.close()

	answerA, err := svc.Join(ctx, callID, 1, EndpointMain, alice.offer())
	if err != nil {
		t.Fatalf("join alice: %v", err)
	}
	answerB, err := svc.Join(ctx, callID, 2, EndpointMain, bob.offer())
	if err != nil {
		t.Fatalf("join bob: %v", err)
	}
	errCh := make(chan error, 2)
	go func() { errCh <- alice.connect(ctx, answerA) }()
	go func() { errCh <- bob.connect(ctx, answerB) }()
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("client connect: %v", err)
		}
	}

	// alice 读 SFU 回投的 RTCP（找 PLI）。
	rtcpCh := make(chan rtcp.Packet, 32)
	go func() {
		for {
			stream, _, err := alice.rtcpSession.AcceptStream()
			if err != nil {
				return
			}
			go func(stream *srtp.ReadStreamSRTCP) {
				buf := make([]byte, 1500)
				for {
					n, err := stream.Read(buf)
					if err != nil {
						return
					}
					pkts, err := rtcp.Unmarshal(buf[:n])
					if err != nil {
						continue
					}
					for _, pkt := range pkts {
						rtcpCh <- pkt
					}
				}
			}(stream)
		}
	}()

	// alice 三层都持续发。
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		seq := uint16(1)
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = alice.sendVideoPacket(base, seq)
				_ = alice.sendVideoPacket(base+2, seq)
				_ = alice.sendVideoPacket(base+4, seq)
				seq++
			}
		}
	}()

	dcB, err := bob.openDataChannel(ctx)
	if err != nil {
		t.Fatalf("bob data channel: %v", err)
	}
	defer dcB.Close()
	endpointID := fmt.Sprintf("audio-%d", alice.ssrc)
	// 先请低层（180→层0），让 SFU 建立「当前转发层0」状态。
	if err := bob.sendReceiverVideoConstraints(dcB, endpointID, 180, 180); err != nil {
		t.Fatalf("bob low constraints: %v", err)
	}
	time.Sleep(500 * time.Millisecond)
	// 升高层（720→层2）：SFU 必须向 alice 要层2 关键帧。
	if err := bob.sendReceiverVideoConstraints(dcB, endpointID, 180, 720); err != nil {
		t.Fatalf("bob high constraints: %v", err)
	}

	deadline := time.After(5 * time.Second)
	for {
		select {
		case pkt := <-rtcpCh:
			if pli, ok := pkt.(*rtcp.PictureLossIndication); ok && pli.MediaSSRC == base+4 {
				_ = svc.CloseRoom(ctx, callID)
				return
			}
		case <-deadline:
			t.Fatalf("publisher never received a PLI for the top layer %#x after the viewer switched up", base+4)
		}
	}
}
