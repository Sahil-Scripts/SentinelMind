async function fetchGraph() {
  const res = await fetch('http://127.0.0.1:8000/graph');
  return await res.json();
}

const colorByTactic = (t) => ({
  "Credential Access": "#ef4444",
  "Lateral Movement": "#f59e0b",
  "Exfiltration": "#3b82f6"
}[t] || "#64748b");

let cy, edges = [];

function initCy(nodes, edgesIn) {
  const elements = [];
  nodes.forEach(n => elements.push({ data: { id: n.id, label: n.id } }));
  edges = edgesIn.sort((a,b)=> (a.stepNum||0) - (b.stepNum||0));
  edges.forEach(e => elements.push({ data: { id: e.source+"->"+e.target+"#"+e.stepNum, source: e.source, target: e.target, color: colorByTactic(e.tactic), stepNum: e.stepNum, label: (e.tactic||"-")+"/"+(e.technique||"-") } }));

  cy = cytoscape({
    container: document.getElementById('graph'),
    elements,
    style: [
      { selector: 'node', style: { 'label': 'data(label)', 'text-valign':'center', 'color':'#111', 'background-color':'#e5e7eb', 'border-color':'#111', 'border-width':1, 'width':36, 'height':36, 'font-size':10 } },
      { selector: 'edge', style: { 'curve-style':'bezier', 'target-arrow-shape':'triangle', 'line-color':'#94a3b8', 'target-arrow-color':'#94a3b8', 'width':2, 'label':'data(label)', 'font-size':8, 'text-background-opacity':1, 'text-background-color':'#fff', 'text-background-padding':2 } },
    ],
    layout: { name: 'cose', animate: true }
  });
}

async function loadGraph() {
  document.getElementById('status').innerText = "Loading...";
  const g = await fetchGraph();
  initCy(g.nodes || [], g.edges || []);
  document.getElementById('status').innerText = "Graph loaded";
}

async function play() {
  if (!cy) return;
  for (const e of edges) {
    const id = e.source+"->"+e.target+"#"+e.stepNum;
    cy.$('edge').style({'line-color':'#94a3b8','target-arrow-color':'#94a3b8'});
    cy.$(`#${CSS.escape(id)}`).style({'line-color': e.color || colorByTactic(e.tactic), 'target-arrow-color': e.color || colorByTactic(e.tactic), 'width':4});
    await new Promise(r => setTimeout(r, 900));
  }
  document.getElementById('status').innerText = "Playback complete";
}

document.getElementById('btnLoad').onclick = loadGraph;
document.getElementById('btnPlay').onclick = play;
document.getElementById('btnReset').onclick = ()=> location.reload();
