import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const SEVERITY_COLORS = {
  CRITICAL: '#ff4444',
  HIGH:     '#ffbb33',
  MEDIUM:   '#ff8800',
  LOW:      '#4499ff',
  INFO:     '#8b949e',
};

const CHAIN_PALETTE = ['#388bfd', '#3fb950', '#e3b341', '#ff7b72', '#a371f7', '#79c0ff'];

function formatVulnName(name) {
  if (!name) return 'Unknown';
  // hidden_endpoint means it's a discovered endpoint with no confirmed vuln yet.
  // Show it with a distinct label rather than the generic "Hidden Endpoint".
  if (name === 'hidden_endpoint') return 'Unconfirmed Endpoint';
  return name.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function endpointPath(url) {
  try { return new URL(url).pathname || '/'; }
  catch { return url.replace(/^https?:\/\/[^/]+/, '') || '/'; }
}

/**
 * Normalize a chain to the "steps" format the graph renderer expects.
 * Backend v1.4 sends chain.nodes + chain.edges; legacy sends chain.steps.
 * hidden_endpoint findings are kept only when they sit between two real vulns
 * (they become context nodes, not vuln nodes).
 */
function chainToSteps(chain) {
  const mapNode = n => ({
    vulnerability: n.type || n.vulnerability || 'unknown',
    endpoint:      n.endpoint || '',
    severity:      (n.severity || 'low').toUpperCase(),
    result:        n.result || n.title || n.description || '',
    confirmed:     !!n.confirmed,
  });

  let steps;
  if (Array.isArray(chain.nodes) && chain.nodes.length > 0) {
    steps = chain.nodes.map(mapNode);
  } else if (Array.isArray(chain.chain_path) && chain.chain_path.length > 0) {
    steps = chain.chain_path.map(mapNode);
  } else {
    steps = (chain.steps || []).map(s => ({ ...mapNode(s) }));
  }

  // Remove trailing hidden_endpoint nodes that have no downstream vulnerability —
  // they pad the chain with noise rather than proof.
  while (steps.length > 1 && steps[steps.length - 1].vulnerability === 'hidden_endpoint') {
    steps.pop();
  }
  return steps;
}

export default function AttackChainGraph({ chains = [], onNodeClick, svgHeight, fitRef }) {
  const svgRef  = useRef(null);
  const zoomRef = useRef(null);

  const normalizedChains = chains.map(c => ({ ...c, _steps: chainToSteps(c) }));
  const multiChains  = normalizedChains.filter(c => c._steps.length >= 2);
  const standalones  = normalizedChains.filter(c => c._steps.length < 2);

  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    if (!normalizedChains.length) return;

    d3.select(el).selectAll('*').remove();

    const width  = el.clientWidth  || 640;
    const height = el.clientHeight || 440;

    // Build node + link sets
    // Multi-step chains contribute edges; standalone chains add isolated nodes
    const nodesMap = new Map();
    const links    = [];

    normalizedChains.forEach((chain, chainIdx) => {
      const steps = chain._steps || [];
      if (steps.length === 0) return;

      steps.forEach((step, idx) => {
        const nodeId = `${step.vulnerability}|${step.endpoint}`;
        if (!nodesMap.has(nodeId)) {
          nodesMap.set(nodeId, {
            id:         nodeId,
            label:      step.vulnerability,
            endpoint:   step.endpoint || '',
            severity:   (step.severity || 'LOW').toUpperCase(),
            result:     step.result || '',
            chainIdx,
            standalone: steps.length < 2,
          });
        }
        // Only add edges for multi-step chains
        if (idx > 0 && steps.length >= 2) {
          const prevStep = steps[idx - 1];
          const prevId   = `${prevStep.vulnerability}|${prevStep.endpoint}`;
          links.push({
            source:   prevId,
            target:   nodeId,
            chainIdx,
            label: (prevStep.result || '').replace(/\.$/, '').slice(0, 24),
          });
        }
      });
    });

    const nodes = Array.from(nodesMap.values());
    if (!nodes.length) return;

    const svg = d3.select(el)
      .attr('width',   width)
      .attr('height',  height)
      .attr('viewBox', `0 0 ${width} ${height}`);

    // Per-severity arrow markers
    const defs = svg.append('defs');
    Object.entries(SEVERITY_COLORS).forEach(([sev, color]) => {
      defs.append('marker')
        .attr('id',          `arrow-${sev}`)
        .attr('viewBox',     '0 -4 8 8')
        .attr('refX',        24)
        .attr('refY',        0)
        .attr('markerWidth', 5)
        .attr('markerHeight', 5)
        .attr('orient',      'auto')
        .append('path')
        .attr('d',    'M0,-4L8,0L0,4')
        .attr('fill', color)
        .attr('opacity', 0.7);
    });

    const g = svg.append('g');

    const zoom = d3.zoom().scaleExtent([0.1, 8]).on('zoom', e => g.attr('transform', e.transform));
    svg.call(zoom);
    zoomRef.current = zoom;

    if (fitRef) {
      fitRef.current = () => {
        svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);
      };
    }

    // Stronger repulsion when all nodes are standalone (no edges pull them together)
    const chargeStrength = links.length === 0 ? -180 : -340;
    const linkDistance   = links.length === 0 ? 0    : 140;

    const simulation = d3.forceSimulation(nodes)
      .force('link',      d3.forceLink(links).id(d => d.id).distance(linkDistance))
      .force('charge',    d3.forceManyBody().strength(chargeStrength))
      .force('center',    d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(44));

    // Edge lines (only exist for multi-step chains)
    const link = g.append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', d => CHAIN_PALETTE[d.chainIdx % CHAIN_PALETTE.length])
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.55)
      .attr('marker-end', d => {
        const tgtSev = nodesMap.get(typeof d.target === 'object' ? d.target.id : d.target)?.severity || 'LOW';
        return `url(#arrow-${tgtSev})`;
      });

    // Edge labels
    const edgeLabel = g.append('g')
      .selectAll('text')
      .data(links)
      .join('text')
      .attr('text-anchor', 'middle')
      .attr('font-size',   '7px')
      .attr('fill',        d => CHAIN_PALETTE[d.chainIdx % CHAIN_PALETTE.length])
      .attr('opacity',     0.85)
      .attr('pointer-events', 'none')
      .text(d => d.label);

    // Node groups
    const node = g.append('g')
      .selectAll('g')
      .data(nodes)
      .join('g')
      .style('cursor', 'pointer')
      .call(
        d3.drag()
          .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
          .on('drag',  (e, d) => { d.fx = e.x; d.fy = e.y; })
          .on('end',   (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
      )
      .on('click', (e, d) => { if (onNodeClick) onNodeClick(d); });

    // Outer glow ring (dashed for standalone nodes)
    node.append('circle')
      .attr('r',              22)
      .attr('fill',           'none')
      .attr('stroke',         d => SEVERITY_COLORS[d.severity] || '#8b949e')
      .attr('stroke-width',   1)
      .attr('stroke-opacity', 0.3)
      .attr('stroke-dasharray', d => d.standalone ? '3 2' : 'none');

    // Main circle
    node.append('circle')
      .attr('r',            18)
      .attr('fill',         d => SEVERITY_COLORS[d.severity] || '#8b949e')
      .attr('fill-opacity', d => d.standalone ? 0.55 : 0.9)
      .attr('stroke',       '#0d1117')
      .attr('stroke-width', 2);

    // Severity initial
    node.append('text')
      .attr('dy',          4)
      .attr('text-anchor', 'middle')
      .attr('font-size',   '11px')
      .attr('font-weight', 'bold')
      .attr('fill',        '#0d1117')
      .attr('pointer-events', 'none')
      .text(d => d.severity[0]);

    // Vuln name below circle
    node.append('text')
      .attr('dy',          34)
      .attr('text-anchor', 'middle')
      .attr('font-size',   '8.5px')
      .attr('fill',        '#c9d1d9')
      .attr('pointer-events', 'none')
      .text(d => {
        const n = formatVulnName(d.label);
        return n.length > 20 ? n.slice(0, 18) + '…' : n;
      });

    // Endpoint path below name
    node.append('text')
      .attr('dy',          46)
      .attr('text-anchor', 'middle')
      .attr('font-size',   '7px')
      .attr('fill',        '#6e7681')
      .attr('pointer-events', 'none')
      .text(d => {
        const ep = d.endpoint.replace(/^https?:\/\/[^/]+/, '') || '/';
        return ep.length > 22 ? ep.slice(0, 20) + '…' : ep;
      });

    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      edgeLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2 - 5);

      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    return () => simulation.stop();
  }, [chains, onNodeClick, fitRef, svgHeight]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!chains || chains.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-[#8b949e] text-sm">
        No attack chains to visualize.
      </div>
    );
  }

  return (
    <div className="w-full rounded-xl overflow-hidden bg-[#0d1117] border border-[#30363d]">

      {/* Info bar */}
      <div className="flex items-center gap-4 px-4 py-2 border-b border-[#30363d] text-xs text-[#8b949e]">
        {multiChains.length > 0 ? (
          <span className="text-[#3fb950] font-medium">
            {multiChains.length} multi-step chain{multiChains.length !== 1 ? 's' : ''}
          </span>
        ) : (
          <span className="text-[#e3b341] font-medium">
            No multi-step chains detected
          </span>
        )}
        {standalones.length > 0 && (
          <span>{standalones.length} standalone vuln{standalones.length !== 1 ? 's' : ''}</span>
        )}
        <span className="ml-auto opacity-60">Drag nodes · Scroll to zoom</span>
      </div>

      {/* D3 graph — always rendered when there are any chains */}
      <svg ref={svgRef} className="w-full" style={{ height: svgHeight ?? 440 }} />

      {/* Severity legend */}
      <div className="flex items-center flex-wrap gap-4 px-4 py-2.5 border-t border-[#30363d] text-xs text-[#8b949e]">
        {multiChains.length === 0 && (
          <span className="text-[#8b949e] italic mr-2">
            Showing {standalones.length} standalone vulnerabilities — chain relationships will appear as more vuln types are found.
          </span>
        )}
        {Object.entries(SEVERITY_COLORS).map(([sev, color]) => (
          <span key={sev} className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full inline-block" style={{ background: color }} />
            {sev}
          </span>
        ))}
      </div>
    </div>
  );
}
