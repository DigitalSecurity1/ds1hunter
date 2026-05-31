import React, { useEffect, useRef, useState, useCallback } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import axios from 'axios';
import AttackChainGraph from '../components/AttackChainGraph';

const SEV_COLOR = {
  CRITICAL: '#ff4444',
  HIGH:     '#ffbb33',
  MEDIUM:   '#ff8800',
  LOW:      '#4499ff',
  INFO:     '#8b949e',
};
const ALL_SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

function fmt(name) {
  return (name || '').replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

export default function GraphFullPage() {
  const { huntId }  = useParams();
  const navigate    = useNavigate();
  const fitRef      = useRef(null);

  const [hunt,        setHunt]        = useState(null);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState('');
  const [sevFilter,   setSevFilter]   = useState(new Set(ALL_SEVS));
  const [selected,    setSelected]    = useState(null);
  const [verifying,   setVerifying]   = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);

  useEffect(() => {
    axios.get(`/api/hunts/${huntId}/`)
      .then(r => { setHunt(r.data); setLoading(false); })
      .catch(() => { setError('Failed to load hunt data.'); setLoading(false); });
  }, [huntId]);

  const rawChains = hunt?.results?.attack_chains || hunt?.attack_chains || [];

  // Filter chain steps by active severity buttons.
  // Chains may arrive as chain.steps (legacy) or chain.nodes (v1.4+).
  const chains = rawChains
    .map(chain => {
      const stepsSource = chain.steps || chain.nodes || chain.chain_path || [];
      const filtered = stepsSource.filter(
        s => sevFilter.has((s.severity || 'LOW').toUpperCase())
      );
      return { ...chain, steps: filtered };
    })
    .filter(c => c.steps.length > 0);

  const handleVerify = useCallback(async (node) => {
    if (!node || verifying) return;
    setVerifying(true);
    setVerifyResult(null);
    try {
      const res = await axios.post(`/api/hunts/${huntId}/verify-finding/`, {
        vuln_type: node.label,
        endpoint:  node.endpoint,
        method:    'GET',
      });
      setVerifyResult(res.data);
    } catch (err) {
      setVerifyResult({
        confirmed:  false,
        confidence: 0,
        detail:     err?.response?.data?.detail || 'Verification request failed.',
      });
    } finally {
      setVerifying(false);
    }
  }, [huntId, verifying]);

  const totalNodes = new Set(
    chains.flatMap(c => c.steps.map(s => `${s.vulnerability}|${s.endpoint}`))
  ).size;

  const toggleSev = sev =>
    setSevFilter(prev => {
      const next = new Set(prev);
      next.has(sev) ? next.delete(sev) : next.add(sev);
      return next;
    });

  // ── SVG height = viewport minus the two bars ────────────────────────────
  // top bar ≈ 48px, info/legend bar inside graph ≈ 60px  → leave some room
  const svgHeight = 'calc(100vh - 48px - 96px)';

  if (loading) return (
    <div className="flex items-center justify-center h-screen bg-[#0d1117] text-[#8b949e] text-sm">
      Loading attack graph…
    </div>
  );
  if (error) return (
    <div className="flex items-center justify-center h-screen bg-[#0d1117] text-[#f85149] text-sm">
      {error}
    </div>
  );

  const riskColor = hunt?.risk_score >= 9 ? '#ff4444'
    : hunt?.risk_score >= 7 ? '#ffbb33'
    : '#4499ff';

  return (
    <div className="flex flex-col h-screen bg-[#0d1117] overflow-hidden select-none">

      {/* ── Top bar ── */}
      <div className="flex items-center gap-3 px-4 py-2.5 bg-[#161b22] border-b border-[#30363d] shrink-0 h-12">

        {/* Back / close */}
        <button
          onClick={() => { if (window.opener) window.close(); else navigate(-1); }}
          className="flex items-center gap-1.5 text-[#8b949e] hover:text-[#c9d1d9] text-xs shrink-0"
          title="Close"
        >
          <span className="text-base leading-none">←</span>
          <span className="hidden sm:inline">Back</span>
        </button>

        <div className="w-px h-4 bg-[#30363d] shrink-0" />

        {/* Hunt target */}
        <span className="text-[#c9d1d9] text-sm font-medium truncate max-w-[260px] shrink-0">
          {hunt?.target || 'Attack Graph'}
        </span>

        {/* Risk badge */}
        {hunt?.risk_score != null && (
          <span className="text-[10px] px-2 py-0.5 rounded-full border shrink-0"
            style={{ color: riskColor, borderColor: riskColor + '44', background: riskColor + '12' }}>
            Risk {hunt.risk_score}/10
          </span>
        )}

        {/* Stats */}
        <span className="text-[#8b949e] text-xs shrink-0">
          {chains.length} chain{chains.length !== 1 ? 's' : ''} · {totalNodes} node{totalNodes !== 1 ? 's' : ''}
        </span>

        {/* Severity toggles - right side */}
        <div className="flex items-center gap-1.5 ml-auto">
          {ALL_SEVS.map(sev => (
            <button
              key={sev}
              onClick={() => toggleSev(sev)}
              title={`Toggle ${sev}`}
              className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] border transition-all"
              style={{
                borderColor: SEV_COLOR[sev] + '55',
                background:  sevFilter.has(sev) ? SEV_COLOR[sev] + '22' : 'transparent',
                color:       sevFilter.has(sev) ? SEV_COLOR[sev] : '#555',
              }}
            >
              <span className="font-bold">{sev[0]}</span>
              <span className="hidden lg:inline">{sev.slice(1).toLowerCase()}</span>
            </button>
          ))}

          <div className="w-px h-4 bg-[#30363d] mx-1" />

          {/* Reset zoom */}
          <button
            onClick={() => fitRef.current?.()}
            className="px-2.5 py-0.5 rounded text-[10px] bg-[#21262d] text-[#8b949e] hover:text-[#c9d1d9] border border-[#30363d]"
            title="Reset zoom to center"
          >
            ⊡ Reset
          </button>
        </div>
      </div>

      {/* ── Graph area ── */}
      <div className="relative flex flex-1 overflow-hidden">

        {/* Graph canvas */}
        <div className="flex-1 overflow-hidden">
          <AttackChainGraph
            chains={chains}
            onNodeClick={setSelected}
            fitRef={fitRef}
            svgHeight={svgHeight}
          />
        </div>

        {/* ── Node detail panel (slide in from right) ── */}
        {selected && (
          <div className="absolute inset-y-0 right-0 w-72 bg-[#161b22] border-l border-[#30363d] flex flex-col overflow-hidden z-10">

            {/* Panel header */}
            <div className="flex items-center justify-between px-4 py-3 border-b border-[#30363d] shrink-0">
              <span className="text-sm font-semibold text-[#c9d1d9]">Node Detail</span>
              <button
                onClick={() => { setSelected(null); setVerifyResult(null); }}
                className="text-[#8b949e] hover:text-[#c9d1d9] text-lg leading-none"
              >
                ✕
              </button>
            </div>

            {/* Panel body */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">

              <div>
                <div className="text-[#8b949e] uppercase tracking-wider text-[9px] mb-1">Vulnerability</div>
                <div className="text-[#c9d1d9] font-medium text-sm leading-snug">
                  {fmt(selected.label)}
                </div>
              </div>

              <div>
                <div className="text-[#8b949e] uppercase tracking-wider text-[9px] mb-1">Severity</div>
                <span
                  className="inline-block px-2 py-0.5 rounded text-[11px] font-bold"
                  style={{
                    background: (SEV_COLOR[selected.severity] || '#8b949e') + '22',
                    color:       SEV_COLOR[selected.severity] || '#8b949e',
                  }}
                >
                  {selected.severity}
                </span>
              </div>

              <div>
                <div className="text-[#8b949e] uppercase tracking-wider text-[9px] mb-1">Endpoint</div>
                <div className="font-mono text-[#58a6ff] break-all leading-relaxed">
                  {selected.endpoint || '-'}
                </div>
              </div>

              {selected.result && (
                <div>
                  <div className="text-[#8b949e] uppercase tracking-wider text-[9px] mb-1">Proof / Result</div>
                  <div className="text-[#3fb950] leading-relaxed">{selected.result}</div>
                </div>
              )}

              {/* Verify button */}
              {selected.label !== 'hidden_endpoint' && selected.label !== 'Unconfirmed Endpoint' && (
                <div>
                  <button
                    onClick={() => { setVerifyResult(null); handleVerify(selected); }}
                    disabled={verifying}
                    className="w-full mt-1 px-3 py-1.5 rounded text-xs font-bold transition-all
                      bg-[#1f6feb22] border border-[#1f6feb55] text-[#58a6ff]
                      hover:bg-[#1f6feb44] hover:border-[#58a6ff] disabled:opacity-40 disabled:cursor-not-allowed"
                  >
                    {verifying ? '⏳ Verifying…' : '⚡ Re-verify Exploit'}
                  </button>

                  {verifyResult && (
                    <div className={`mt-2 p-2 rounded text-xs border
                      ${verifyResult.confirmed
                        ? 'bg-[#3fb95020] border-[#3fb95055] text-[#3fb950]'
                        : 'bg-[#f8514920] border-[#f8514955] text-[#f85149]'}`}>
                      <div className="font-bold mb-1">
                        {verifyResult.confirmed ? '✓ Confirmed' : '✗ Not confirmed'}
                        {verifyResult.confidence > 0 && (
                          <span className="ml-2 font-normal opacity-70">
                            ({Math.round(verifyResult.confidence * 100)}% confidence)
                          </span>
                        )}
                      </div>
                      <div className="opacity-80 leading-relaxed">{verifyResult.detail}</div>
                      {verifyResult.evidence?.request && (
                        <div className="mt-1 font-mono text-[9px] opacity-60 break-all">
                          {verifyResult.evidence.request}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Show all chains this node belongs to */}
              <div>
                <div className="text-[#8b949e] uppercase tracking-wider text-[9px] mb-1">In chains</div>
                <div className="space-y-1">
                  {rawChains
                    .filter(c => (c.steps || []).some(
                      s => s.vulnerability === selected.label && s.endpoint === selected.endpoint
                    ))
                    .map((c, i) => (
                      <div key={i}
                        className="px-2 py-1 rounded bg-[#21262d] border border-[#30363d] text-[#8b949e]">
                        <span className="text-[#c9d1d9] font-mono text-[10px]">{c.chain_id || `chain-${i+1}`}</span>
                        {c.risk_score && (
                          <span className="ml-2 text-[9px]">risk {c.risk_score}</span>
                        )}
                      </div>
                    ))
                  }
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
