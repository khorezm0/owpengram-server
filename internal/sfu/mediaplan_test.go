package sfu

import (
	"testing"
	"time"

	"github.com/pion/interceptor/pkg/twcc"
)

// wantsStream 报告订阅端 ep 的选层是否放行发布端 from 的该 ssrc：音频与未声明
// ssrc 恒放行；已声明视频 ssrc（含 RTX）只放行 desiredLayer 那一层。
func (ep *endpoint) wantsStream(from *endpoint, ssrc uint32) bool {
	layer, ok := from.plan.videoLayer(ssrc)
	if ssrc == from.plan.audioSSRC || !ok {
		return true
	}
	desired := ep.desiredLayer(from)
	return desired >= 0 && layer == desired
}

// 层结构契约：SIM 组 sources 低→高即层表；FID 对的第二个 ssrc 是其 RTX；
// 音频 ssrc 与未声明 ssrc 不属于层结构（恒放行，不参与选层）。
func TestBuildMediaPlanSimulcast(t *testing.T) {
	offer := ClientOffer{
		AudioSSRC: 1000,
		SsrcGroups: []SsrcGroup{
			{Semantics: "SIM", Sources: []uint32{1001, 1003, 1005}},
			{Semantics: "FID", Sources: []uint32{1001, 1002}},
			{Semantics: "FID", Sources: []uint32{1003, 1004}},
			{Semantics: "FID", Sources: []uint32{1005, 1006}},
		},
	}
	plan := buildMediaPlan(offer)
	if len(plan.layers) != 3 || plan.layers[0] != 1001 || plan.layers[1] != 1003 || plan.layers[2] != 1005 {
		t.Fatalf("layers = %v, want SIM sources low→high", plan.layers)
	}
	for ssrc, want := range map[uint32]int{1001: 0, 1003: 1, 1005: 2} {
		if got, ok := plan.videoLayer(ssrc); !ok || got != want {
			t.Fatalf("videoLayer(%d) = %d ok=%v, want %d", ssrc, got, ok, want)
		}
	}
	// RTX 归属其媒体层。
	for rtx, media := range map[uint32]uint32{1002: 1001, 1004: 1003, 1006: 1005} {
		want, _ := plan.videoLayer(media)
		if got, ok := plan.videoLayer(rtx); !ok || got != want {
			t.Fatalf("videoLayer(rtx %d) = %d ok=%v, want media layer %d", rtx, got, ok, want)
		}
	}
	// 音频与未声明 ssrc 不参与选层。
	if _, ok := plan.videoLayer(1000); ok {
		t.Fatalf("audio ssrc must not be a video layer")
	}
	if _, ok := plan.videoLayer(9999); ok {
		t.Fatalf("undeclared ssrc must not be a video layer")
	}
	// 全部声明过的视频 ssrc 都可路由（RTCP PLI/NACK 按 media ssrc 找发布端）。
	for _, ssrc := range []uint32{1001, 1002, 1003, 1004, 1005, 1006} {
		if !plan.declared[ssrc] {
			t.Fatalf("ssrc %d must be declared", ssrc)
		}
	}
}

// 单层发布（conference 模式）：无 SIM 组、唯一 FID 组的第一个 ssrc 即主流。
func TestBuildMediaPlanSingleLayer(t *testing.T) {
	plan := buildMediaPlan(ClientOffer{
		AudioSSRC:  2000,
		SsrcGroups: []SsrcGroup{{Semantics: "FID", Sources: []uint32{2001, 2002}}},
	})
	if len(plan.layers) != 1 || plan.layers[0] != 2001 {
		t.Fatalf("layers = %v, want [2001]", plan.layers)
	}
	if got, ok := plan.videoLayer(2001); !ok || got != 0 {
		t.Fatalf("videoLayer(2001) = %d ok=%v, want layer 0", got, ok)
	}
	if got, ok := plan.videoLayer(2002); !ok || got != 0 {
		t.Fatalf("videoLayer(rtx 2002) = %d ok=%v, want layer 0", got, ok)
	}
}

// 纯音频（无视频组）：无层结构，一切放行。
func TestBuildMediaPlanAudioOnly(t *testing.T) {
	plan := buildMediaPlan(ClientOffer{AudioSSRC: 3000})
	if len(plan.layers) != 0 || len(plan.declared) != 0 {
		t.Fatalf("audio-only plan = %+v, want empty", plan)
	}
	if _, ok := plan.videoLayer(3000); ok {
		t.Fatalf("audio ssrc must not be a video layer")
	}
}

// maxHeight → 层序号：层高阶梯 180/360/720，取不超过请求的最高层，
// 请求低于最低层高时退到层 0（宁低勿断流）。
func TestLayerForMaxHeight(t *testing.T) {
	cases := []struct {
		maxHeight, layers, want int
	}{
		{maxHeight: 180, layers: 3, want: 0},
		{maxHeight: 240, layers: 3, want: 0},
		{maxHeight: 360, layers: 3, want: 1},
		{maxHeight: 480, layers: 3, want: 1},
		{maxHeight: 720, layers: 3, want: 2},
		{maxHeight: 1080, layers: 3, want: 2},
		{maxHeight: 720, layers: 2, want: 1},
		{maxHeight: 360, layers: 2, want: 1},
		{maxHeight: 180, layers: 2, want: 0},
		{maxHeight: 720, layers: 1, want: 0},
	}
	for _, c := range cases {
		if got := layerForMaxHeight(c.maxHeight, c.layers); got != c.want {
			t.Fatalf("layerForMaxHeight(%d, %d) = %d, want %d", c.maxHeight, c.layers, got, c.want)
		}
	}
}

// 订阅端选层：音频与未声明 ssrc 恒放行；已声明视频 ssrc 按约束过滤。
func TestWantsStreamPerSubscriber(t *testing.T) {
	publisher := &endpoint{
		kind: EndpointMain,
		plan: buildMediaPlan(ClientOffer{
			AudioSSRC: 1000,
			SsrcGroups: []SsrcGroup{
				{Semantics: "SIM", Sources: []uint32{1001, 1003, 1005}},
				{Semantics: "FID", Sources: []uint32{1001, 1002}},
				{Semantics: "FID", Sources: []uint32{1003, 1004}},
				{Semantics: "FID", Sources: []uint32{1005, 1006}},
			},
		}),
	}
	if publisher.endpointID() != "audio-1000" {
		t.Fatalf("endpointID = %q, want audio-1000", publisher.endpointID())
	}
	subscriber := func() *endpoint {
		return &endpoint{kind: EndpointMain, plan: buildMediaPlan(ClientOffer{AudioSSRC: 2000})}
	}
	// 标记某层「在发」：选层回退按最近发包窗口判定，不发包的层不算数。
	touch := func(ssrc uint32) {
		publisher.plan.lastPacket[ssrc].Store(time.Now().UnixNano())
	}

	// 未收到过约束：退回 v1 行为（恒最低层）。
	bob := subscriber()
	for ssrc, want := range map[uint32]bool{
		1000: true,  // 音频恒放行
		1001: true,  // SIM[0]
		1002: true,  // SIM[0] 的 RTX
		1003: false, // 高层
		1004: false, // 高层的 RTX
		1005: false,
		9999: true, // 未声明 ssrc 放行
	} {
		if got := bob.wantsStream(publisher, ssrc); got != want {
			t.Fatalf("no-constraints: wantsStream(%d) = %v, want %v", ssrc, got, want)
		}
	}

	// 置顶请求（720）：最高层在发，收最高层与其 RTX；
	// 顶层未发包时回退到最高的在发层（见 TestWantsStreamFallsBackToBestActiveLayer）。
	touch(1005)
	pinned := subscriber()
	pinned.setReceiverConstraints(&receiverConstraints{
		constraints: map[string]videoConstraint{
			"audio-1000": {minHeight: 180, maxHeight: 720},
		},
		def: videoConstraint{maxHeight: 0},
	})
	for ssrc, want := range map[uint32]bool{
		1000: true, // 音频恒放行
		1001: false,
		1002: false,
		1003: false,
		1004: false,
		1005: true, // 顶层
		1006: true, // 顶层 RTX
	} {
		if got := pinned.wantsStream(publisher, ssrc); got != want {
			t.Fatalf("pinned 720: wantsStream(%d) = %v, want %v", ssrc, got, want)
		}
	}

	// 网格请求（360）：中间层在发，收中间层。
	touch(1003)
	grid := subscriber()
	grid.setReceiverConstraints(&receiverConstraints{
		constraints: map[string]videoConstraint{
			"audio-1000": {minHeight: 180, maxHeight: 360},
		},
		def: videoConstraint{maxHeight: 0},
	})
	if !grid.wantsStream(publisher, 1003) || grid.wantsStream(publisher, 1005) {
		t.Fatalf("grid 360 must forward layer 1 only")
	}

	// maxHeight=0（Jitsi「不要」语义）：该 endpoint 的视频全断，音频照放。
	muted := subscriber()
	muted.setReceiverConstraints(&receiverConstraints{
		constraints: map[string]videoConstraint{
			"audio-1000": {maxHeight: 0},
		},
		def: videoConstraint{maxHeight: 360},
	})
	for ssrc, want := range map[uint32]bool{
		1000: true,
		1001: false,
		1003: false,
		1005: false,
		1006: false,
	} {
		if got := muted.wantsStream(publisher, ssrc); got != want {
			t.Fatalf("maxHeight 0: wantsStream(%d) = %v, want %v", ssrc, got, want)
		}
	}

	// 未列出的 endpoint 落 defaultConstraints（360）：中间层在发，收中间层。
	touch(1003)
	def := subscriber()
	def.setReceiverConstraints(&receiverConstraints{
		constraints: map[string]videoConstraint{},
		def:         videoConstraint{maxHeight: 360},
	})
	if !def.wantsStream(publisher, 1003) || def.wantsStream(publisher, 1005) {
		t.Fatalf("defaultConstraints 360 must forward layer 1 only")
	}

	// presentation 发布端的 endpoint 键。
	screen := &endpoint{
		kind: EndpointPresentation,
		plan: buildMediaPlan(ClientOffer{
			AudioSSRC:  7000,
			SsrcGroups: []SsrcGroup{{Semantics: "FID", Sources: []uint32{7001, 7002}}},
		}),
	}
	if screen.endpointID() != "presentation-7000" {
		t.Fatalf("presentation endpointID = %q", screen.endpointID())
	}
}

// 宁低勿断流：请求的层没有流时回退到最高的在发层，而不是全断。
// 实况：屏幕共享发布端只编层 0（SIM 两层），订阅端请求 360（层 1）——
// 严格 layer==target 会把唯一在发的层 0 也丢掉，观看端黑屏。
func TestWantsStreamFallsBackToBestActiveLayer(t *testing.T) {
	publisher := &endpoint{
		kind: EndpointMain,
		plan: buildMediaPlan(ClientOffer{
			AudioSSRC: 1000,
			SsrcGroups: []SsrcGroup{
				{Semantics: "SIM", Sources: []uint32{1001, 1003, 1005}},
				{Semantics: "FID", Sources: []uint32{1001, 1002}},
				{Semantics: "FID", Sources: []uint32{1003, 1004}},
				{Semantics: "FID", Sources: []uint32{1005, 1006}},
			},
		}),
	}
	viewer := &endpoint{kind: EndpointMain, plan: buildMediaPlan(ClientOffer{AudioSSRC: 2000})}
	viewer.setReceiverConstraints(&receiverConstraints{
		constraints: map[string]videoConstraint{
			"audio-1000": {minHeight: 180, maxHeight: 720},
		},
		def: videoConstraint{maxHeight: 0},
	})

	// 没有任何层在发（首包前的窗口）：只放行层 0。
	for ssrc, want := range map[uint32]bool{
		1001: true, 1002: true,
		1003: false, 1005: false,
	} {
		if got := viewer.wantsStream(publisher, ssrc); got != want {
			t.Fatalf("no activity: wantsStream(%d) = %v, want %v", ssrc, got, want)
		}
	}

	// 只有层 0 在发（实况：发布端只编低层）：请求 720 仍收层 0。
	publisher.plan.lastPacket[1001].Store(time.Now().UnixNano())
	for ssrc, want := range map[uint32]bool{
		1001: true, 1002: true,
		1003: false, 1005: false,
	} {
		if got := viewer.wantsStream(publisher, ssrc); got != want {
			t.Fatalf("layer 0 only: wantsStream(%d) = %v, want %v", ssrc, got, want)
		}
	}

	// 顶层开始发包：回到严格选层，只收顶层。
	publisher.plan.lastPacket[1005].Store(time.Now().UnixNano())
	for ssrc, want := range map[uint32]bool{
		1001: false, 1002: false,
		1003: false, 1005: true, 1006: true,
	} {
		if got := viewer.wantsStream(publisher, ssrc); got != want {
			t.Fatalf("top active: wantsStream(%d) = %v, want %v", ssrc, got, want)
		}
	}

	// 顶层停发（但曾发过包）：锁定顶层不回退——来回切 ssrc 会使观看端反复
	// 重同步即冻结；停发期间保持最后一帧，等顶层恢复。
	stale := time.Now().Add(-3 * time.Second).UnixNano()
	publisher.plan.lastPacket[1005].Store(stale)
	publisher.plan.lastPacket[1001].Store(time.Now().UnixNano())
	if viewer.wantsStream(publisher, 1001) || !viewer.wantsStream(publisher, 1005) {
		t.Fatalf("paused top layer must stay selected, not fall back to another ssrc")
	}
}

// 冻结回归（2026-11 屏幕共享）：TWCC 记录投递必须非阻塞。反馈循环来不及
// 消费（通道满）时，record 必须立即丢弃返回，绝不阻塞 readStream 的转发
// 路径——否则一次反馈停滞就会卡死发布端的全部流，观看端画面冻结。
func TestPublisherTWCCRecordNeverBlocks(t *testing.T) {
	f := &publisherTWCC{
		rec:   twcc.NewRecorder(1),
		start: time.Now(),
		ch:    make(chan twccRecord, 4),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	// 不启动 loop：通道无人消费。灌满后 record 必须走丢弃分支而非阻塞。
	for i := 0; i < 4; i++ {
		f.ch <- twccRecord{ssrc: 1, seq: uint16(i)}
	}
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			f.record(1, uint16(i))
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("record blocked on a full channel; bandwidth feedback must never stall forwarding")
	}
}
