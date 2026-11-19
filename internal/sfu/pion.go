package sfu

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/datachannel"
	"github.com/pion/dtls/v3"
	dtlsnet "github.com/pion/dtls/v3/pkg/net"
	"github.com/pion/ice/v4"
	"github.com/pion/interceptor/pkg/twcc"
	"github.com/pion/logging"
	"github.com/pion/rtcp"
	"github.com/pion/rtp"
	"github.com/pion/sctp"
	"github.com/pion/srtp/v3"
	"go.uber.org/zap"
)

// PionConfig 是内嵌 SFU 的运行参数。
type PionConfig struct {
	// UDPPort 是单 UDP 监听端口（pion ICE UDPMux，全部 endpoint 复用）。
	UDPPort int
	// AdvertiseIP 是写进下行 candidate 的客户端可达地址。⚠ 127.0.0.1 会让
	// 真机 ICE 永远连不上且无任何 RPC 错误（纯媒体面静默失败）。
	AdvertiseIP string
	Logger      *zap.Logger
	// Touch 是媒体面活性回报钩子：对仍存活（近期 SRTP 收包/ICE 连通）的
	// endpoint 周期性刷新 group_call_participants.last_check_date，使 sweeper 的
	// 单一水位同时承载「心跳 ∨ 媒体活性」（P0-2 双过期判据的实现方式）。
	Touch func(callID, userID int64)
	// LivenessInterval 是活性回报周期（默认 15s，远小于 sweeper 的 45s TTL）。
	LivenessInterval time.Duration
	// ActivityWindow 判定 endpoint 媒体面存活的最近收包窗口（默认 25s）。
	ActivityWindow time.Duration
}

// pionSFU 是 Service 的 pion 实现：full-ICE CONTROLLING + DTLS 主动握手（client
// 角色，对应下行 setup:"active"）+ SRTP 房间内转发（保留 audio-level 等 RTP
// 扩展，speaking 指示由客户端渲染）。音频原样转发；视频选层后改写到发布端 SIM[0]
// ssrc（见 rewrite.go）。
type pionSFU struct {
	cfg         PionConfig
	log         *zap.Logger
	udpConn     net.PacketConn
	mux         *ice.UDPMuxDefault
	cert        tls.Certificate
	fingerprint string

	mu    sync.Mutex
	rooms map[int64]*room

	cancel context.CancelFunc
}

type epKey struct {
	userID int64
	kind   EndpointKind
}

type room struct {
	callID    int64
	endpoints map[epKey]*endpoint
}

// mediaPlan 是一个发布 endpoint 的视频层结构（Join 时从 ssrc-groups 还原）：
// layers 是 SIM 组的有序 ssrc 表（低→高）；单层发布（conference 模式）退化为
// 唯一 FID 组的主流。转发按订阅端 ReceiverVideoConstraints 逐包选层：
// RTX（FID 对）随其媒体层同进退；音频与未声明 ssrc 不参与选层、恒放行。
type mediaPlan struct {
	audioSSRC uint32
	layers    []uint32          // SIM 层 ssrc，低→高
	layerOf   map[uint32]int    // 媒体 ssrc → 层序号
	rtxOf     map[uint32]uint32 // RTX ssrc → 其媒体 ssrc
	declared  map[uint32]bool   // ssrc-groups 里出现过的全部视频 ssrc
	// 每个已声明视频 ssrc 的最近 RTP 时刻（unix nano）。「宁低勿断流」回退
	// 用它判断哪些层真的在发包：请求的层没有流时退到最高的在发层。
	lastPacket map[uint32]*atomic.Int64
}

func buildMediaPlan(offer ClientOffer) mediaPlan {
	plan := mediaPlan{
		audioSSRC: offer.AudioSSRC,
		layerOf:   make(map[uint32]int),
		rtxOf:     make(map[uint32]uint32),
		declared:  make(map[uint32]bool),
	}
	for _, g := range offer.SsrcGroups {
		if g.Semantics == "SIM" && len(g.Sources) > 0 {
			plan.layers = append(plan.layers, g.Sources...) // sources 低→高
			break
		}
	}
	// 单层发布（conference 模式）没有 SIM 组：唯一组的第一个 ssrc 即主流。
	if len(plan.layers) == 0 && len(offer.SsrcGroups) == 1 && len(offer.SsrcGroups[0].Sources) > 0 {
		plan.layers = []uint32{offer.SsrcGroups[0].Sources[0]}
	}
	for i, ssrc := range plan.layers {
		plan.layerOf[ssrc] = i
	}
	for _, g := range offer.SsrcGroups {
		for _, ssrc := range g.Sources {
			plan.declared[ssrc] = true
		}
		if g.Semantics == "FID" && len(g.Sources) == 2 {
			plan.rtxOf[g.Sources[1]] = g.Sources[0]
		}
	}
	plan.lastPacket = make(map[uint32]*atomic.Int64, len(plan.declared))
	for ssrc := range plan.declared {
		plan.lastPacket[ssrc] = new(atomic.Int64)
	}
	return plan
}

// layerActiveWindow 内有 RTP 的层视为「在发」；与 tgcalls 的约束降级延迟
// （2s）同量级——发布端按 SenderVideoConstraints 停发高层后，订阅端在
// 同一窗口内回退到低层，不断流。
const layerActiveWindow = 2 * time.Second

// transport-wide-cc 的 RTP 头扩展 id（与下行 SDP buildGroupCallConnectionParams
// 的 rtp-hdrexts 一致：客户端硬编码 id=3）。SFU 用它从发布端 RTP 取传输层序号。
const transportWideCCExtID = 3

// bestActiveLayer 返回最近窗口内真正在发包的最高层；没有任何层在发时
// 返回 0（层 0 的首包在转发判定前已记录，正常流不会走到全无分支）。
func (p mediaPlan) bestActiveLayer() int {
	best := -1
	now := time.Now().UnixNano()
	for i, ssrc := range p.layers {
		if t := p.lastPacket[ssrc]; t != nil && now-t.Load() < int64(layerActiveWindow) {
			best = i
		}
	}
	if best < 0 {
		return 0
	}
	return best
}

// videoLayer 返回已声明视频 ssrc 所属的层（RTX 归属其媒体层）；
// ok=false 表示未声明（音频/探测流：不参与选层，恒放行）。
func (p mediaPlan) videoLayer(ssrc uint32) (layer int, ok bool) {
	if media, isRTX := p.rtxOf[ssrc]; isRTX {
		layer, ok = p.layerOf[media]
		return layer, ok
	}
	layer, ok = p.layerOf[ssrc]
	return layer, ok
}

// layerForMaxHeight 把订阅端 maxHeight 请求映射到层序号。层高按 tweb/tgcalls
// 的 simulcast 阶梯假设：层 i 高度 = 180 << i（180/360/720）。取不超过请求的
// 最高层；请求低于最低层高时退到层 0（宁低勿断流）。
func layerForMaxHeight(maxHeight, layerCount int) int {
	best := 0
	for i := 1; i < layerCount; i++ {
		if 180<<i <= maxHeight {
			best = i
		}
	}
	return best
}

type endpoint struct {
	callID int64
	userID int64
	kind   EndpointKind
	plan   mediaPlan
	sfu    *pionSFU

	agent  *ice.Agent
	demux  *demuxer
	closed chan struct{}

	mu           sync.Mutex
	writeStream  *srtp.WriteStreamSRTP
	rtcpWriter   *srtp.WriteStreamSRTCP
	lastActivity time.Time
	connected    bool
	closeOnce    sync.Once

	// 订阅端视频意愿（data channel 上的 ReceiverVideoConstraints）：
	// nil = 尚未收到过任何约束，退回 v1 行为（恒最低层）。
	recvMu sync.RWMutex
	recv   *receiverConstraints

	// 订阅端对各发布端 endpoint 的视频改写状态（endpointID→forwarder）：选中层
	// 改写到发布端 SIM[0] ssrc 上（见 rewrite.go）。
	fwdMu sync.Mutex
	fwd   map[string]*videoForwarder
}

// videoConstraint 是订阅端对单个 endpoint 的视频请求（Jitsi 语义：
// maxHeight<=0 = 不要该 endpoint 的视频）。
type videoConstraint struct {
	minHeight int
	maxHeight int
}

// receiverConstraints 是一条 ReceiverVideoConstraints 消息解析后的快照。
type receiverConstraints struct {
	constraints map[string]videoConstraint
	def         videoConstraint
}

func (ep *endpoint) setReceiverConstraints(c *receiverConstraints) {
	ep.recvMu.Lock()
	ep.recv = c
	ep.recvMu.Unlock()
}

// endpointID 与信令面 rpc.groupCallEndpointID 同式（rpc 层铸造并写进
// participant.video.endpoint / presentation.endpoint）：客户端的
// ReceiverVideoConstraints 以该串为键，必须逐字节一致。
func (ep *endpoint) endpointID() string {
	if ep.kind == EndpointPresentation {
		return fmt.Sprintf("presentation-%d", ep.plan.audioSSRC)
	}
	return fmt.Sprintf("audio-%d", ep.plan.audioSSRC)
}

// targetLayerFor 返回本端对发布端 endpoint 的目标层：-1 = 不收该 endpoint 的
// 视频（maxHeight<=0）；从未收到 ReceiverVideoConstraints 时退回 v1 行为
// （恒最低层）。层高映射见 layerForMaxHeight。
func (ep *endpoint) targetLayerFor(publisherEndpointID string, layerCount int) int {
	ep.recvMu.RLock()
	defer ep.recvMu.RUnlock()
	if ep.recv == nil {
		return 0
	}
	c, ok := ep.recv.constraints[publisherEndpointID]
	if !ok {
		c = ep.recv.def
	}
	if c.maxHeight <= 0 {
		return -1
	}
	return layerForMaxHeight(c.maxHeight, layerCount)
}

// desiredLayer 返回订阅端 ep 当前应收发布端 from 的视频层（-1 = 不要视频）。
func (ep *endpoint) desiredLayer(from *endpoint) int {
	target := ep.targetLayerFor(from.endpointID(), len(from.plan.layers))
	if target < 0 {
		return -1
	}
	// 请求层从未发过包（发布端只编低层/尚未升上来）：回退到最高的在发层，
	// 避免黑屏。
	if target < len(from.plan.layers) {
		if t := from.plan.lastPacket[from.plan.layers[target]]; t == nil || t.Load() == 0 {
			return from.plan.bestActiveLayer()
		}
	}
	// 请求层一旦发过包就锁定它：屏幕共享静态画面会让高层短暂停发，停发期间
	// 保持最后一帧，不来回切层。
	return target
}

// NewPion 启动内嵌 SFU：绑定 UDP 端口、生成进程级 DTLS 证书。
func NewPion(cfg PionConfig) (Service, error) {
	if cfg.UDPPort <= 0 {
		return nil, fmt.Errorf("sfu: invalid udp port %d", cfg.UDPPort)
	}
	if cfg.AdvertiseIP == "" {
		cfg.AdvertiseIP = "127.0.0.1"
	}
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.LivenessInterval <= 0 {
		cfg.LivenessInterval = 15 * time.Second
	}
	if cfg.ActivityWindow <= 0 {
		cfg.ActivityWindow = 25 * time.Second
	}
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: cfg.UDPPort})
	if err != nil {
		return nil, fmt.Errorf("sfu: listen udp %d: %w", cfg.UDPPort, err)
	}
	cert, fingerprint, err := newDTLSCertificate()
	if err != nil {
		_ = udpConn.Close()
		return nil, err
	}
	s := &pionSFU{
		cfg:         cfg,
		log:         cfg.Logger,
		udpConn:     udpConn,
		mux:         ice.NewUDPMuxDefault(ice.UDPMuxParams{UDPConn: udpConn}),
		cert:        cert,
		fingerprint: fingerprint,
		rooms:       make(map[int64]*room),
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.livenessLoop(ctx)
	s.log.Info("sfu listening",
		zap.Int("udp_port", cfg.UDPPort),
		zap.String("advertise_ip", cfg.AdvertiseIP))
	if cfg.AdvertiseIP == "127.0.0.1" {
		s.log.Warn("TELESRV_SFU_ADVERTISE_IP is 127.0.0.1: real devices' ICE won't be able to connect (media-only silent failure); multi-device testing requires the host's LAN IP")
	}
	return s, nil
}

func (s *pionSFU) Enabled() bool { return true }

// Join 为参与者建立媒体 endpoint：本端生成独立 ufrag/pwd，ICE CONTROLLING 等待
// 客户端 Binding Request（上行 JSON 无 candidates，对端地址靠 peer-reflexive 学得），
// 连通后以 DTLS client 主动握手并建 SRTP 会话。
func (s *pionSFU) Join(ctx context.Context, callID, userID int64, kind EndpointKind, offer ClientOffer) (ServerAnswer, error) {
	if offer.Ufrag == "" || offer.Pwd == "" {
		return ServerAnswer{}, fmt.Errorf("sfu: empty remote ice credentials")
	}
	localUfrag, err := randomICEString(8)
	if err != nil {
		return ServerAnswer{}, err
	}
	localPwd, err := randomICEString(24)
	if err != nil {
		return ServerAnswer{}, err
	}
	agent, err := ice.NewAgent(&ice.AgentConfig{
		NetworkTypes:    []ice.NetworkType{ice.NetworkTypeUDP4},
		CandidateTypes:  []ice.CandidateType{ice.CandidateTypeHost},
		UDPMux:          s.mux,
		LocalUfrag:      localUfrag,
		LocalPwd:        localPwd,
		IncludeLoopback: true,
		LoggerFactory:   &pionLoggerFactory{log: s.log.Named("ice")},
	})
	if err != nil {
		return ServerAnswer{}, fmt.Errorf("sfu: new ice agent: %w", err)
	}
	// pion 要求注册 OnCandidate 才能收集；候选地址由我们直接以
	// AdvertiseIP:UDPPort 写进下行 JSON，回调本身无需消费。
	if err := agent.OnCandidate(func(ice.Candidate) {}); err != nil {
		_ = agent.Close()
		return ServerAnswer{}, fmt.Errorf("sfu: on candidate: %w", err)
	}
	if err := agent.GatherCandidates(); err != nil {
		_ = agent.Close()
		return ServerAnswer{}, fmt.Errorf("sfu: gather candidates: %w", err)
	}
	ep := &endpoint{
		callID: callID,
		userID: userID,
		kind:   kind,
		plan:   buildMediaPlan(offer),
		sfu:    s,
		agent:  agent,
		closed: make(chan struct{}),
	}
	s.attachEndpoint(ep)
	go ep.run(offer)
	return ServerAnswer{
		Ufrag:             localUfrag,
		Pwd:               localPwd,
		FingerprintSHA256: s.fingerprint,
		Candidates: []Candidate{{
			IP:       s.cfg.AdvertiseIP,
			Port:     s.cfg.UDPPort,
			Protocol: "udp",
			Type:     "host",
		}},
	}, nil
}

func (s *pionSFU) attachEndpoint(ep *endpoint) {
	key := epKey{userID: ep.userID, kind: ep.kind}
	s.mu.Lock()
	rm, ok := s.rooms[ep.callID]
	if !ok {
		rm = &room{callID: ep.callID, endpoints: make(map[epKey]*endpoint)}
		s.rooms[ep.callID] = rm
	}
	old := rm.endpoints[key]
	rm.endpoints[key] = ep
	var oldPresentation *endpoint
	if ep.kind == EndpointMain {
		// 主连接 rejoin：旧 presentation 登记一并作废（信令侧同样清 presentation_json，
		// 客户端随后重发 joinGroupCallPresentation）。
		pk := epKey{userID: ep.userID, kind: EndpointPresentation}
		oldPresentation = rm.endpoints[pk]
		delete(rm.endpoints, pk)
	}
	s.mu.Unlock()
	if old != nil {
		old.close() // rejoin：替换旧 endpoint
	}
	if oldPresentation != nil {
		oldPresentation.close()
	}
}

func (s *pionSFU) Leave(_ context.Context, callID, userID int64, kind EndpointKind) error {
	var victims []*endpoint
	s.mu.Lock()
	if rm, ok := s.rooms[callID]; ok {
		keys := []epKey{{userID: userID, kind: kind}}
		if kind == EndpointMain {
			// 整体离会从不补发 leaveGroupCallPresentation：主 endpoint 离开联动拆屏幕。
			keys = append(keys, epKey{userID: userID, kind: EndpointPresentation})
		}
		for _, key := range keys {
			if ep := rm.endpoints[key]; ep != nil {
				victims = append(victims, ep)
				delete(rm.endpoints, key)
			}
		}
		if len(rm.endpoints) == 0 {
			delete(s.rooms, callID)
		}
	}
	s.mu.Unlock()
	for _, ep := range victims {
		ep.close()
	}
	return nil
}

func (s *pionSFU) CloseRoom(_ context.Context, callID int64) error {
	s.mu.Lock()
	rm := s.rooms[callID]
	delete(s.rooms, callID)
	s.mu.Unlock()
	if rm != nil {
		for _, ep := range rm.endpoints {
			ep.close()
		}
	}
	return nil
}

func (s *pionSFU) AliveUserIDs(callID int64) []int64 {
	cutoff := time.Now().Add(-s.cfg.ActivityWindow)
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, ok := s.rooms[callID]
	if !ok {
		return nil
	}
	seen := make(map[int64]bool)
	var out []int64
	for key, ep := range rm.endpoints {
		// 任一连接（主/屏幕）存活即视为该参与者媒体面存活。
		if !seen[key.userID] && ep.aliveSince(cutoff) {
			seen[key.userID] = true
			out = append(out, key.userID)
		}
	}
	return out
}

// livenessLoop 周期性把媒体面存活回报给信令侧（刷新保活水位）。
func (s *pionSFU) livenessLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.LivenessInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.cfg.Touch == nil {
				continue
			}
			cutoff := time.Now().Add(-s.cfg.ActivityWindow)
			type key struct{ callID, userID int64 }
			seen := make(map[key]bool)
			var alive []key
			s.mu.Lock()
			for callID, rm := range s.rooms {
				for ek, ep := range rm.endpoints {
					k := key{callID, ek.userID}
					if !seen[k] && ep.aliveSince(cutoff) {
						seen[k] = true
						alive = append(alive, k)
					}
				}
			}
			s.mu.Unlock()
			for _, k := range alive {
				s.cfg.Touch(k.callID, k.userID)
			}
		}
	}
}

// forwardRTP 把一条解密后的 RTP 包按订阅裁剪后转发给房间内其他参与者的**主**
// endpoint（扩展头随包透传——audio-level 即 speaking 指示数据源；观看屏幕共享也
// 走观看者的主连接，presentation 连接不收任何远端流）。音频与未声明 ssrc 原样
// 转发；已声明视频按每个订阅端的 ReceiverVideoConstraints 选层，并改写到发布端
// SIM[0] ssrc 上（订阅端只为 SIM[0] 建接收流，见 rewrite.go）。未收到约束的
// 订阅端退回 v1 行为（恒最低层）。
func (s *pionSFU) forwardRTP(from *endpoint, ssrc uint32, packet []byte) {
	layer, isVideo := from.plan.videoLayer(ssrc)
	now := time.Now()
	for _, ep := range s.mainTargets(from) {
		if !isVideo {
			ep.writeRTP(packet)
			continue
		}
		f := ep.forwarderFor(from)
		res := f.forward(ssrc, layer, ep.desiredLayer(from), packet, now)
		if res.pliSSRC != 0 {
			from.writeRTCP(&rtcp.PictureLossIndication{MediaSSRC: res.pliSSRC})
		}
		if res.out != nil {
			ep.writeRTP(res.out)
		}
	}
}

// forwarderFor 返回（按需创建）订阅端 ep 对发布端 from 的视频改写状态。以
// 发布端指针校验：发布端 rejoin 后 endpoint ID 不变但层结构可能变。
func (ep *endpoint) forwarderFor(from *endpoint) *videoForwarder {
	key := from.endpointID()
	ep.fwdMu.Lock()
	defer ep.fwdMu.Unlock()
	if ep.fwd == nil {
		ep.fwd = make(map[string]*videoForwarder)
	}
	f := ep.fwd[key]
	if f == nil || f.pub != from {
		f = newVideoForwarder(from)
		ep.fwd[key] = f
	}
	return f
}

// forwarderByOutSSRC 找到输出 ssrc（发布端 SIM[0] 或其 RTX）为该值的改写状态，
// 供订阅端 RTCP（PLI/NACK）反查源层。
func (ep *endpoint) forwarderByOutSSRC(ssrc uint32) *videoForwarder {
	ep.fwdMu.Lock()
	defer ep.fwdMu.Unlock()
	if ssrc == 0 {
		return nil
	}
	for _, f := range ep.fwd {
		if f.outSSRC == ssrc || (f.outRTX != 0 && f.outRTX == ssrc) {
			return f
		}
	}
	return nil
}

// mainTargets 返回房间内除 from 所属参与者外的全部主 endpoint。
func (s *pionSFU) mainTargets(from *endpoint) []*endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, ok := s.rooms[from.callID]
	if !ok {
		return nil
	}
	targets := make([]*endpoint, 0, len(rm.endpoints))
	for key, ep := range rm.endpoints {
		if key.userID != from.userID && key.kind == EndpointMain {
			targets = append(targets, ep)
		}
	}
	return targets
}

// publisherBySSRC 找到房间内声明了该 ssrc（音频/任一视频层/RTX）的发布 endpoint，
// 供 RTCP 反馈（PLI/NACK）按 media ssrc 路由回发布端。房间规模小，直接遍历。
func (s *pionSFU) publisherBySSRC(callID int64, ssrc uint32) *endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	rm, ok := s.rooms[callID]
	if !ok {
		return nil
	}
	for _, ep := range rm.endpoints {
		if ep.plan.audioSSRC == ssrc || ep.plan.declared[ssrc] {
			return ep
		}
	}
	return nil
}

// ---- endpoint ----

func (ep *endpoint) run(offer ClientOffer) {
	s := ep.sfu
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// CONTROLLING：主动发起连通性检查；对端候选靠带 ufrag/pwd 认证的
	// Binding Request 学得（peer-reflexive）。
	conn, err := ep.agent.Dial(ctx, offer.Ufrag, offer.Pwd)
	if err != nil {
		s.log.Debug("sfu ice dial", zap.Int64("call_id", ep.callID), zap.Int64("user_id", ep.userID), zap.Error(err))
		ep.close()
		return
	}
	ep.markActivity()
	ep.demux = newDemuxer(conn)

	dtlsConfig := &dtls.Config{
		Certificates:         []tls.Certificate{s.cert},
		InsecureSkipVerify:   true, // 身份校验走指纹（信令面 commit），非 CA 链
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{
			dtls.SRTP_AEAD_AES_128_GCM,
			dtls.SRTP_AES128_CM_HMAC_SHA1_80,
		},
	}
	dtlsRaw := ep.demux.dtlsConn()
	dtlsConn, err := dtls.Client(dtlsnet.PacketConnFromConn(dtlsRaw), dtlsRaw.RemoteAddr(), dtlsConfig)
	if err != nil {
		s.log.Debug("sfu dtls client", zap.Int64("user_id", ep.userID), zap.Error(err))
		ep.close()
		return
	}
	// pion/dtls v3 构造器是惰性握手（首次读写才握手）：必须显式 HandshakeContext
	// 完成并设硬上限，否则 ConnectionState 拿不到状态、停滞的握手会挂死 goroutine。
	hsCtx, hsCancel := context.WithTimeout(context.Background(), 20*time.Second)
	err = dtlsConn.HandshakeContext(hsCtx)
	hsCancel()
	if err != nil {
		s.log.Debug("sfu dtls handshake", zap.Int64("user_id", ep.userID), zap.Error(err))
		ep.close()
		return
	}
	// 指纹核验：DTLS 证书必须与 join JSON 承诺的 sha-256 指纹一致。
	state, ok := dtlsConn.ConnectionState()
	if !ok || len(state.PeerCertificates) == 0 {
		ep.close()
		return
	}
	gotFP, err := certificateFingerprint(state.PeerCertificates[0])
	if err != nil || normalizeFingerprint(gotFP) != normalizeFingerprint(offer.FingerprintSHA256) {
		s.log.Warn("sfu dtls fingerprint mismatch", zap.Int64("user_id", ep.userID))
		ep.close()
		return
	}
	profile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok {
		ep.close()
		return
	}
	srtpConfig := &srtp.Config{}
	switch profile {
	case dtls.SRTP_AEAD_AES_128_GCM:
		srtpConfig.Profile = srtp.ProtectionProfileAeadAes128Gcm
	case dtls.SRTP_AES128_CM_HMAC_SHA1_80:
		srtpConfig.Profile = srtp.ProtectionProfileAes128CmHmacSha1_80
	default:
		ep.close()
		return
	}
	// SFU 是 DTLS client：isClient=true 决定 SRTP 读写密钥方向。
	if err := srtpConfig.ExtractSessionKeysFromDTLS(&state, true); err != nil {
		s.log.Debug("sfu srtp keys", zap.Error(err))
		ep.close()
		return
	}
	session, err := srtp.NewSessionSRTP(ep.demux.srtpConn(), srtpConfig)
	if err != nil {
		s.log.Debug("sfu srtp session", zap.Error(err))
		ep.close()
		return
	}
	writeStream, err := session.OpenWriteStream()
	if err != nil {
		ep.close()
		return
	}
	// RTCP 升级为 SRTCP session（同一份 srtpConfig 复用）：读侧做 PLI/NACK 路由，
	// 写侧供把反馈转投给发布端。注意：建了 SessionSRTCP 后绝不能再裸读
	// srtcpConn（双读互偷包）。
	rtcpSession, err := srtp.NewSessionSRTCP(ep.demux.srtcpConn(), srtpConfig)
	if err != nil {
		s.log.Debug("sfu srtcp session", zap.Error(err))
		ep.close()
		return
	}
	rtcpWriter, err := rtcpSession.OpenWriteStream()
	if err != nil {
		ep.close()
		return
	}
	ep.mu.Lock()
	ep.writeStream = writeStream
	ep.rtcpWriter = rtcpWriter
	ep.connected = true
	ep.mu.Unlock()
	ep.markActivity()
	s.log.Info("sfu endpoint connected",
		zap.Int64("call_id", ep.callID),
		zap.Int64("user_id", ep.userID),
		zap.Int("kind", int(ep.kind)))

	go ep.serveRTCP(rtcpSession)
	// SCTP 数据通道骑在同一条 DTLS 连接上（握手后的 application data 即 SCTP 包）。
	go ep.serveData(dtlsConn)

	// transport-cc 终结：按本端收到的发布端 RTP 生成 TWCC 反馈回投（见
	// publisherTWCC）。记录与转发解耦，反馈写绝不阻塞转发。生命周期绑在本
	// goroutine：run 退出即 close，避免与 close() 竞争共享字段。
	twccFB := newPublisherTWCC(ep)
	defer twccFB.close()

	// 入站 SRTP：全部流进入转发路径——视频层的取舍是逐包按订阅端过滤
	//（readStream→forwardRTP），音频与未声明 ssrc 恒放行。
	for {
		stream, ssrc, err := session.AcceptStream()
		if err != nil {
			ep.close()
			return
		}
		go ep.readStream(stream, ssrc, twccFB)
	}
}

// publisherTWCC 终结 transport-cc：记录本端收到的发布端 RTP 的传输层序号，
// 周期性生成 TWCC 反馈写回发布端。发布端→SFU 这段没有选层裁剪，序号连续，
// 反馈如实反映链路带宽——发布端的带宽估计据此升码率、编高层。
//
// 记录与转发彻底解耦：record 只做非阻塞通道投递（满则丢），Record/生成/
// RTCP 写全部在独立的 loop goroutine。带宽反馈的任何阻塞或耗时都绝不拖住
// readStream 的转发路径（否则一次写阻塞/一次大反馈生成就会卡死整个发布端
// 的所有流，表现为观看端画面冻结）。
type twccRecord struct {
	ssrc    uint32
	seq     uint16
	arrival int64
}

type publisherTWCC struct {
	ep    *endpoint
	rec   *twcc.Recorder
	start time.Time
	ch    chan twccRecord
	stop  chan struct{}
	done  chan struct{}
}

func newPublisherTWCC(ep *endpoint) *publisherTWCC {
	f := &publisherTWCC{
		ep:    ep,
		rec:   twcc.NewRecorder(rand.Uint32()),
		start: time.Now(),
		ch:    make(chan twccRecord, 1024),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go f.loop()
	return f
}

// record 由 readStream 逐包调用：非阻塞投递，通道满即丢弃该条记录。宁可
// 反馈少报（发布端略降码率），也绝不阻塞转发。同一 endpoint 的全部流（音频/
// 各视频层/RTX）共享一个记录器：传输层序号本就跨流连续，合并记录才不会把
// 选层裁剪误报成丢包。recorder 仅由 loop 单 goroutine 访问，无需加锁。
func (f *publisherTWCC) record(ssrc uint32, seq uint16) {
	select {
	case f.ch <- twccRecord{ssrc: ssrc, seq: seq, arrival: time.Since(f.start).Microseconds()}:
	default:
	}
}

func (f *publisherTWCC) loop() {
	defer close(f.done)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-f.stop:
			return
		case p := <-f.ch:
			f.rec.Record(p.ssrc, p.seq, p.arrival)
		case <-ticker.C:
			for _, pkt := range f.rec.BuildFeedbackPacket() {
				f.ep.writeRTCP(pkt)
			}
		}
	}
}

func (f *publisherTWCC) close() {
	close(f.stop)
	<-f.done
}

func (ep *endpoint) readStream(stream *srtp.ReadStreamSRTP, ssrc uint32, twccFB *publisherTWCC) {
	buf := make([]byte, 1500)
	var hdr rtp.Header
	for {
		n, err := stream.Read(buf)
		if err != nil {
			return
		}
		ep.markActivity()
		if t := ep.plan.lastPacket[ssrc]; t != nil {
			t.Store(time.Now().UnixNano())
		}
		if twccFB != nil {
			if _, herr := hdr.Unmarshal(buf[:n]); herr == nil {
				if ext := hdr.GetExtension(transportWideCCExtID); len(ext) >= 2 {
					twccFB.record(ssrc, binary.BigEndian.Uint16(ext[:2]))
				}
			}
		}
		packet := make([]byte, n)
		copy(packet, buf[:n])
		ep.sfu.forwardRTP(ep, ssrc, packet)
	}
}

// serveRTCP 消费本 endpoint 的入站 RTCP 并路由：
//   - PLI / FIR / NACK（订阅端反馈）→ 按 media ssrc 找到发布 endpoint 转投——
//     恒等转发下订阅端反馈里的 ssrc 就是发布端的原始 ssrc，无需改写；
//     发布端自带 RTX 重传与 300ms keyframe 限流；
//   - SR（发布端报告）→ 转发给其他主 endpoint（A/V 同步的 NTP↔RTP 映射来源）；
//   - RR（订阅端接收报告）→ 按 media ssrc 回投发布端：订阅端只收被选中的层，
//     该层的 RR 干净（无选层裁剪丢包），给发布端提供接收端存活/RTT/丢包信号；
//   - REMB / transport-cc（订阅端带宽反馈）→ 丢弃，不回投。订阅端只收到被选层
//     裁剪后的流：其 transport-cc 把 SFU 故意丢的其它层报成丢包，REMB 只反映
//     低层接收码率——回投会让发布端带宽估计崩塌/被压低、停编高层（屏幕共享
//     升 720p 即黑屏回落 360p 的根因）。发布端带宽反馈由 SFU 自产：publisherTWCC
//     按发布端→SFU 这段（无裁剪、序号连续）的收包回投 transport-cc，如实反映
//     链路带宽，发布端据此升码率、编高层。
func (ep *endpoint) serveRTCP(session *srtp.SessionSRTCP) {
	for {
		stream, _, err := session.AcceptStream()
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
				ep.markActivity()
				pkts, err := rtcp.Unmarshal(buf[:n])
				if err != nil {
					continue
				}
				ep.routeRTCP(pkts)
			}
		}()
	}
}

func (ep *endpoint) routeRTCP(pkts []rtcp.Packet) {
	for _, pkt := range pkts {
		switch fb := pkt.(type) {
		case *rtcp.PictureLossIndication:
			ep.routeKeyframeRequest(fb.MediaSSRC, pkt)
		case *rtcp.FullIntraRequest:
			ep.routeKeyframeRequest(fb.MediaSSRC, pkt)
		case *rtcp.TransportLayerNack:
			ep.routeNACK(fb)
		case *rtcp.ReceiverReport:
			if len(fb.Reports) > 0 {
				ep.sfu.writeRTCPToPublisher(ep.callID, fb.Reports[0].SSRC, pkt)
			}
		case *rtcp.SenderReport:
			// 视频层 SR 按各订阅端的改写状态换算（只转当前层）；音频等原样转发。
			_, isVideo := ep.plan.videoLayer(fb.SSRC)
			for _, target := range ep.sfu.mainTargets(ep) {
				if !isVideo {
					target.writeRTCP(pkt)
					continue
				}
				if sr := target.forwarderFor(ep).translateSR(fb); sr != nil {
					target.writeRTCP(sr)
				}
			}
		}
	}
}

// routeKeyframeRequest：订阅端对改写后输出 ssrc 的 PLI/FIR 转成对源层的 PLI
// （待切层优先）；其它 ssrc（未改写的流）按原 ssrc 路由。
func (ep *endpoint) routeKeyframeRequest(mediaSSRC uint32, pkt rtcp.Packet) {
	if f := ep.forwarderByOutSSRC(mediaSSRC); f != nil {
		if src := f.keyframeSSRC(); src != 0 {
			f.pub.writeRTCP(&rtcp.PictureLossIndication{MediaSSRC: src})
		}
		return
	}
	ep.sfu.writeRTCPToPublisher(ep.callID, mediaSSRC, pkt)
}

// routeNACK：订阅端 NACK 的是输出序号空间，按改写历史还原成 源层 ssrc + 源序号
// 后转投发布端（发布端自带 RTX 重传，重传包再经 rewriteRTX 改写回来）。
func (ep *endpoint) routeNACK(fb *rtcp.TransportLayerNack) {
	f := ep.forwarderByOutSSRC(fb.MediaSSRC)
	if f == nil {
		ep.sfu.writeRTCPToPublisher(ep.callID, fb.MediaSSRC, fb)
		return
	}
	var seqs []uint16
	for i := range fb.Nacks {
		seqs = append(seqs, fb.Nacks[i].PacketList()...)
	}
	for srcSSRC, srcSeqs := range f.translateNACK(seqs) {
		f.pub.writeRTCP(&rtcp.TransportLayerNack{
			SenderSSRC: fb.SenderSSRC,
			MediaSSRC:  srcSSRC,
			Nacks:      rtcp.NackPairsFromSequenceNumbers(srcSeqs),
		})
	}
}

func (s *pionSFU) writeRTCPToPublisher(callID int64, mediaSSRC uint32, pkt rtcp.Packet) {
	publisher := s.publisherBySSRC(callID, mediaSSRC)
	if publisher != nil {
		publisher.writeRTCP(pkt)
	}
}

func (ep *endpoint) writeRTCP(pkt rtcp.Packet) {
	ep.mu.Lock()
	w := ep.rtcpWriter
	ep.mu.Unlock()
	if w == nil {
		return
	}
	raw, err := rtcp.Marshal([]rtcp.Packet{pkt})
	if err != nil {
		return
	}
	_, _ = w.Write(raw)
}

// serveData 在 DTLS 连接上被动承接 SCTP 关联与 DCEP data channel：
//   - 客户端总是 SCTP INIT 与 DATA_CHANNEL_OPEN 的发起方（sid=0, label="data"），
//     SFU 绝不主动 OPEN（客户端没有 accept 入站 OPEN 的逻辑）；
//   - 关联被客户端重建（restartDataChannel）时在同一 DTLS 上重新 accept；
//   - 数据通道上没有任何消息是音视频工作的硬前置：v2 消费
//     ReceiverVideoConstraints（订阅端选层意愿），其余消息忽略。
func (ep *endpoint) serveData(conn *dtls.Conn) {
	logf := logging.NewDefaultLoggerFactory()
	logf.DefaultLogLevel = logging.LogLevelError
	for {
		select {
		case <-ep.closed:
			return
		default:
		}
		assoc, err := sctp.Server(sctp.Config{
			NetConn:       conn,
			LoggerFactory: logf,
		})
		if err != nil {
			return // DTLS 关闭/endpoint 拆除
		}
		for {
			dc, err := datachannel.Accept(assoc, &datachannel.Config{LoggerFactory: logf})
			if err != nil {
				break // 关联结束：外层重试承接客户端重建的新关联
			}
			go ep.serveDataChannel(dc)
		}
		_ = assoc.Close()
	}
}

func (ep *endpoint) serveDataChannel(dc *datachannel.DataChannel) {
	defer func() { _ = dc.Close() }()
	buf := make([]byte, 65536)
	for {
		n, isString, err := dc.ReadDataChannel(buf)
		if err != nil {
			return
		}
		if !isString || n == 0 {
			continue
		}
		ep.markActivity()
		var msg struct {
			ColibriClass string `json:"colibriClass"`
			Constraints  map[string]struct {
				MinHeight int `json:"minHeight"`
				MaxHeight int `json:"maxHeight"`
			} `json:"constraints"`
			DefaultConstraints struct {
				MaxHeight int `json:"maxHeight"`
			} `json:"defaultConstraints"`
			OnStageEndpoints []string `json:"onStageEndpoints"`
		}
		if err := json.Unmarshal(buf[:n], &msg); err != nil {
			continue
		}
		// ReceiverVideoConstraints（tweb streamManager / tgcalls 同源，Jitsi
		// colibri 语义）：constraints 按发布端 endpoint 键控，defaultConstraints
		// 兜底未列出的 endpoint（maxHeight<=0 = 不要）。onStageEndpoints 仅记录，
		// 选层以 constraints 为准（pinned 的 ask 已在 constraints 里）。
		if msg.ColibriClass == "ReceiverVideoConstraints" {
			c := &receiverConstraints{
				constraints: make(map[string]videoConstraint, len(msg.Constraints)),
				def:         videoConstraint{maxHeight: msg.DefaultConstraints.MaxHeight},
			}
			for endpointID, constraint := range msg.Constraints {
				c.constraints[endpointID] = videoConstraint{minHeight: constraint.MinHeight, maxHeight: constraint.MaxHeight}
			}
			ep.setReceiverConstraints(c)
			continue
		}
		ep.sfu.log.Debug("sfu data channel message",
			zap.Int64("call_id", ep.callID),
			zap.Int64("user_id", ep.userID),
			zap.String("colibri_class", msg.ColibriClass))
	}
}

func (ep *endpoint) writeRTP(packet []byte) {
	ep.mu.Lock()
	ws := ep.writeStream
	ep.mu.Unlock()
	if ws == nil {
		return
	}
	_, _ = ws.Write(packet)
}

func (ep *endpoint) markActivity() {
	ep.mu.Lock()
	ep.lastActivity = time.Now()
	ep.mu.Unlock()
}

func (ep *endpoint) aliveSince(cutoff time.Time) bool {
	ep.mu.Lock()
	defer ep.mu.Unlock()
	return ep.connected && ep.lastActivity.After(cutoff)
}

func (ep *endpoint) close() {
	ep.closeOnce.Do(func() {
		close(ep.closed)
		if ep.demux != nil {
			ep.demux.Close()
		}
		_ = ep.agent.Close()
		ep.mu.Lock()
		ep.connected = false
		ep.mu.Unlock()
	})
}

// pionLoggerFactory 把 pion 日志降为静默（按需可接 zap）。
type pionLoggerFactory struct{ log *zap.Logger }

func (f *pionLoggerFactory) NewLogger(scope string) logging.LeveledLogger {
	return logging.NewDefaultLoggerFactory().NewLogger(scope)
}
