package dag

import (
	"fmt"
	"math"

	"github.com/Fantom-foundation/lachesis-base/abft"
	"github.com/Fantom-foundation/lachesis-base/gossip/dagordering"
	"github.com/Fantom-foundation/lachesis-base/hash"
	"github.com/Fantom-foundation/lachesis-base/inter/dag"
	"github.com/Fantom-foundation/lachesis-base/inter/idx"
	"github.com/Fantom-foundation/lachesis-base/kvdb/memorydb"
	"github.com/ethereum/go-ethereum/log"
	"gonum.org/v1/gonum/graph"
	"gonum.org/v1/gonum/graph/encoding"

	"github.com/Fantom-foundation/go-opera/gossip"
	"github.com/Fantom-foundation/go-opera/integration"
	"github.com/Fantom-foundation/go-opera/inter"
	"github.com/Fantom-foundation/go-opera/inter/iblockproc"
	"github.com/Fantom-foundation/go-opera/utils/adapters/vecmt2dagidx"
	"github.com/Fantom-foundation/go-opera/vecmt"
)

// graphInMem implements dot.Graph over inmem refs and nodes
type graphInMem struct {
	refs  []hash.Event
	nodes map[hash.Event]*dotNode
	attrs struct {
		graph attributer
		edge  attributer
	}
}

// readDagGraph read gossip.Store into inmem dot.Graph
func readDagGraph(gdb *gossip.Store, cfg integration.Configs, from, to idx.Epoch) *graphInMem {
	g := &graphInMem{
		refs:  make([]hash.Event, 0, 2000000),
		nodes: make(map[hash.Event]*dotNode),
		attrs: struct{ graph, edge attributer }{
			attributer(make(map[string]string, 10)),
			attributer(make(map[string]string, 10)),
		},
	}

	g.attrs.graph.setAttr("clusterrank", "local")
	g.attrs.graph.setAttr("compound", "true")
	g.attrs.graph.setAttr("newrank", "true")
	g.attrs.graph.setAttr("ranksep", "0.05")

	cdb := abft.NewMemStore()
	defer cdb.Close()
	// ApplyGenesis()
	cdb.SetEpochState(&abft.EpochState{
		Epoch: from,
	})
	cdb.SetLastDecidedState(&abft.LastDecidedState{
		LastDecidedFrame: abft.FirstFrame - 1,
	})

	dagIndexer := vecmt.NewIndex(panics("Vector clock"), cfg.VectorClock)
	orderer := abft.NewOrderer(
		cdb,
		&integration.GossipStoreAdapter{gdb},
		vecmt2dagidx.Wrap(dagIndexer),
		panics("Lachesis"),
		cfg.Lachesis)
	err := orderer.Bootstrap(abft.OrdererCallbacks{})
	if err != nil {
		panic(err)
	}

	var (
		epoch     idx.Epoch
		prevBS    *iblockproc.BlockState
		processed map[hash.Event]dag.Event
	)

	readRestoredAbftStore := func() {
		bs, _ := gdb.GetHistoryBlockEpochState(epoch)

		for f := idx.Frame(0); f <= cdb.GetLastDecidedFrame(); f++ {
			rr := cdb.GetFrameRoots(f)
			for _, r := range rr {
				node := g.nodes[r.ID]
				markAsRoot(node)
			}
		}

		if prevBS != nil {

			maxBlock := idx.Block(math.MaxUint64)
			if bs != nil {
				maxBlock = bs.LastBlock.Idx
			}

			for n := prevBS.LastBlock.Idx + 1; n <= maxBlock; n++ {
				block := gdb.GetBlock(n)
				if block == nil {
					break
				}
				node, exists := g.nodes[block.Atropos]
				if exists {
					markAsAtropos(node)
				}
			}
		}

		prevBS = bs
	}

	resetToNewEpoch := func() {
		validators := gdb.GetHistoryEpochState(epoch).Validators
		processed = make(map[hash.Event]dag.Event, 1000)
		err := orderer.Reset(epoch, validators)
		if err != nil {
			panic(err)
		}
		dagIndexer.Reset(validators, memorydb.New(), func(id hash.Event) dag.Event {
			return gdb.GetEvent(id)
		})
	}

	buffer := dagordering.New(
		cfg.Opera.Protocol.DagProcessor.EventsBufferLimit,
		dagordering.Callback{
			Process: func(e dag.Event) error {
				processed[e.ID()] = e
				err = dagIndexer.Add(e)
				if err != nil {
					panic(err)
				}
				dagIndexer.Flush()
				orderer.Process(e)

				id := len(g.refs)
				g.refs = append(g.refs, e.ID())
				g.nodes[e.ID()] = newDotNode(int64(id), e)
				return nil
			},
			Released: func(e dag.Event, peer string, err error) {
				if err != nil {
					panic(err)
				}
			},
			Get: func(id hash.Event) dag.Event {
				return processed[id]
			},
			Exists: func(id hash.Event) bool {
				_, ok := processed[id]
				return ok
			},
		})

	// process events
	gdb.ForEachEvent(from, func(e *inter.EventPayload) bool {
		// current epoch is finished, so process accumulated events
		if epoch < e.Epoch() {
			readRestoredAbftStore()

			epoch = e.Epoch()
			// break after last epoch:
			if to >= from && epoch > to {
				return false
			}

			resetToNewEpoch()
		}

		buffer.PushEvent(e, "")

		return true
	})
	epoch++
	readRestoredAbftStore()

	return g
}

func (g *graphInMem) DOTID() string {
	return "DAG"
}

// DOTAttributers are graph.Graph values that specify top-level DOT attributes.
func (g *graphInMem) DOTAttributers() (graph, node, edge encoding.Attributer) {
	graph = g.attrs.graph
	node = attributer(make(map[string]string, 0)) // empty
	edge = g.attrs.edge
	return
}

// Node returns the node with the given ID if it exists
// in the graph, and nil otherwise.
func (g *graphInMem) Node(id int64) graph.Node {
	hash := g.refs[id]
	return g.nodes[hash]
}

// Nodes returns all the nodes in the graph.
//
// Nodes must not return nil.
func (g *graphInMem) Nodes() graph.Nodes {
	nn := &dagNodes{
		data: make(chan *dotNode),
	}

	go func() {
		defer close(nn.data)

		for _, e := range g.nodes {
			nn.data <- e
		}
	}()

	return nn
}

// From returns all nodes that can be reached directly
// from the node with the given ID.
//
// From must not return nil.
func (g *graphInMem) From(id int64) graph.Nodes {
	nn := &dagNodes{
		data: make(chan *dotNode),
	}

	h := g.refs[id]
	x := g.nodes[h]
	go func() {
		defer close(nn.data)
		for _, p := range x.parents {
			n := g.nodes[p]
			nn.data <- n
		}
	}()

	return nn
}

// To returns all nodes that can reach directly
// to the node with the given ID.
//
// To must not return nil.
func (g *graphInMem) To(id int64) graph.Nodes {
	nn := &dagNodes{
		data: make(chan *dotNode),
	}
	close(nn.data)
	return nn
}

// HasEdgeBetween returns whether an edge exists between
// nodes with IDs xid and yid without considering direction.
func (g *graphInMem) HasEdgeBetween(xid, yid int64) bool {
	x := g.nodes[g.refs[xid]]
	y := g.nodes[g.refs[yid]]

	for _, p := range x.parents {
		if p == y.hash {
			return true
		}
	}
	for _, p := range y.parents {
		if p == x.hash {
			return true
		}
	}

	return false
}

// HasEdgeFromTo returns whether an edge exists
// in the graph from u to v with IDs uid and vid.
func (g *graphInMem) HasEdgeFromTo(uid, vid int64) bool {
	u := g.nodes[g.refs[uid]]
	v := g.nodes[g.refs[vid]]

	for _, p := range u.parents {
		if p == v.hash {
			return true
		}
	}

	return false
}

// Edge returns the edge from u to v, with IDs uid and vid,
// if such an edge exists and nil otherwise. The node v
// must be directly reachable from u as defined by the
// From method.
func (g *graphInMem) Edge(uid, vid int64) graph.Edge {
	u := g.nodes[g.refs[uid]]
	v := g.nodes[g.refs[vid]]

	for _, p := range u.parents {
		if p == v.hash {
			return &dotEdge{
				x: u,
				y: v,
			}
		}
	}

	return nil
}

func panics(name string) func(error) {
	return func(err error) {
		log.Crit(fmt.Sprintf("%s error", name), "err", err)
	}
}

func markAsRoot(n *dotNode) {
	n.setAttr("xlabel", "root")
	n.setAttr("style", "filled")
	n.setAttr("fillcolor", "#FFFF00")
}

func markAsAtropos(n *dotNode) {
	n.setAttr("xlabel", "atropos")
	n.setAttr("style", "filled")
	n.setAttr("fillcolor", "#FF0000")
}