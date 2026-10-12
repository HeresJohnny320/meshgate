package ops

import (
	"testing"

	"github.com/heresjohnny320/meshgate/internal/model"
	"github.com/heresjohnny320/meshgate/internal/store"
)

func service(t *testing.T, selfKind model.NodeKind) *Service {
	t.Helper()
	s, _ := store.Open("", "self")
	s.Put(model.Key(model.KindNode, "self"), model.Node{ID: "self", Name: "pfsense", Kind: selfKind}, store.Cluster)
	s.Put(model.Key(model.KindNode, "lap"), model.Node{ID: "lap", Name: "laptop", Kind: model.NodeClient}, store.Cluster)
	return &Service{Store: s, SelfID: "self"}
}

func TestPutACL(t *testing.T) {
	o := service(t, model.NodeServer)
	good := model.ACL{Node: "self", From: []string{"lap"}, To: "192.168.20.0/24", Proto: "tcp", Ports: "80,443,8000-8100", Enabled: true}
	a, err := o.PutACL(good, store.Cluster)
	if err != nil || a.ID == "" || a.Name != "192.168.20.0/24" {
		t.Fatalf("good rule: %+v %v", a, err)
	}
	bad := []model.ACL{
		{Node: "lap", To: "self", Proto: "any"},                           // enforced on a client
		{Node: "self", From: []string{"ghost"}, To: "self", Proto: "any"}, // unknown device
		{Node: "self", To: "nas.local", Proto: "tcp"},                     // not an IP
		{Node: "self", To: "self", Proto: "icmp", Ports: "80"},            // ports without tcp/udp
		{Node: "self", To: "self", Proto: "tcp", Ports: "90-80"},          // reversed range
		{Node: "self", To: "self", Proto: "gre"},                          // unknown proto
	}
	for i, b := range bad {
		if _, err := o.PutACL(b, store.Cluster); err == nil {
			t.Errorf("bad rule %d accepted: %+v", i, b)
		}
	}
	if _, err := service(t, model.NodeClient).PutACL(good, store.Cluster); err == nil {
		t.Error("client node wrote a rule")
	}
}

func TestToggleKeepsScope(t *testing.T) {
	o := service(t, model.NodeServer)
	o.Store.Put(model.Key(model.KindNode, "home"), model.Node{ID: "home", Name: "home", Kind: model.NodeServer}, store.Cluster)
	f, err := o.PutForward(model.Forward{Name: "mc", Proto: "tcp", EdgeNode: "self", ListenPort: 25565, TargetNode: "home", TargetPort: 25565, Enabled: true}, store.Local)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Toggle(model.KindForward, f.ID, false); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get[model.Forward](o.Store, model.Key(model.KindForward, f.ID))
	if got.Enabled || got.Name != "mc" || !o.Store.IsLocal(model.Key(model.KindForward, f.ID)) {
		t.Fatalf("toggle: %+v local=%v", got, o.Store.IsLocal(model.Key(model.KindForward, f.ID)))
	}
	if err := o.Toggle(model.KindNode, "home", false); err == nil {
		t.Fatal("nodes cannot be toggled")
	}
}

func TestLANPolicyPatchAndRemoveNodeDropsRules(t *testing.T) {
	o := service(t, model.NodeServer)
	o.Store.Put(model.Key(model.KindNode, "home"), model.Node{ID: "home", Name: "home", Kind: model.NodeServer}, store.Cluster)
	r := model.PolicyRestricted
	n, err := o.UpdateNode("home", NodePatch{LANPolicy: &r}, store.Cluster)
	if err != nil || !n.Restricted() {
		t.Fatalf("patch: %+v %v", n, err)
	}
	bogus := "closed"
	if _, err := o.UpdateNode("home", NodePatch{LANPolicy: &bogus}, store.Cluster); err == nil {
		t.Fatal("bad policy accepted")
	}
	a, _ := o.PutACL(model.ACL{Node: "home", To: "self", Proto: "any", Enabled: true}, store.Cluster)
	if err := o.RemoveNode("home"); err != nil {
		t.Fatal(err)
	}
	if _, ok := o.Store.Raw(model.Key(model.KindACL, a.ID)); ok {
		t.Fatal("rule of removed node kept")
	}
}
