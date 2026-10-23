import { useMemo, useState } from 'react'
import type { Topology } from '../types'

const trustColor: Record<string, string> = {
  trusted: '#34d399',
  unknown: '#94a3b8',
  noncompliant: '#f59e0b',
  quarantined: '#fb923c',
  compromised: '#f43f5e',
}

const severityColor: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#f59e0b',
  low: '#38bdf8',
  info: '#475569',
}

interface Layout {
  segments: Array<{ id: string; label: string; cidr?: string; sensitivity?: string; y: number; height: number; count: number }>
  assets: Array<{ id: string; label: string; ip?: string; x: number; y: number; trust: string; criticality: number; segmentId: string | null }>
}

const WIDTH = 1000
const ROW_HEIGHT = 108
const NODE_RADIUS = 13

/**
 * Deterministic layout: segments are horizontal lanes, devices are placed on a
 * fixed grid inside their lane. No physics loop, so the picture is stable across
 * refreshes and readable on tablets.
 */
function buildLayout(data: Topology): Layout {
  const segments = data.nodes.filter((node) => node.type === 'segment')
  const assets = data.nodes.filter((node) => node.type === 'asset')
  const laneIndex = new Map<string, number>()
  segments.forEach((segment, index) => laneIndex.set(segment.id, index))
  const unassignedLane = segments.length

  const laidOutSegments = segments.map((segment, index) => ({
    id: segment.id,
    label: segment.label,
    cidr: segment.cidr,
    sensitivity: segment.sensitivity,
    y: 24 + index * ROW_HEIGHT,
    height: ROW_HEIGHT - 18,
    count: assets.filter((asset) => asset.segment_id === segment.id).length,
  }))

  const perLane = new Map<number, number>()
  const laidOutAssets = assets.map((asset) => {
    const lane = asset.segment_id && laneIndex.has(asset.segment_id) ? laneIndex.get(asset.segment_id)! : unassignedLane
    const indexInLane = perLane.get(lane) ?? 0
    perLane.set(lane, indexInLane + 1)
    const columns = 9
    const column = indexInLane % columns
    const row = Math.floor(indexInLane / columns)
    return {
      id: asset.id,
      label: asset.label,
      ip: asset.ip,
      trust: asset.trust_state ?? 'unknown',
      criticality: asset.criticality ?? 1,
      segmentId: asset.segment_id ?? null,
      x: 250 + column * 78,
      y: 24 + lane * ROW_HEIGHT + 24 + row * 30,
    }
  })

  return { segments: laidOutSegments, assets: laidOutAssets }
}

export function TopologyGraph({
  data,
  onSelectAsset,
  activeAssetId,
}: {
  data: Topology
  onSelectAsset?: (assetId: string) => void
  activeAssetId?: string | null
}) {
  const [showSuspiciousOnly, setShowSuspiciousOnly] = useState(false)
  const [hovered, setHovered] = useState<string | null>(null)
  const layout = useMemo(() => buildLayout(data), [data])
  const nodeIndex = useMemo(() => new Map(layout.assets.map((asset) => [asset.id, asset])), [layout])

  const laneCount = Math.max(1, layout.segments.length + (layout.assets.some((a) => !a.segmentId) ? 1 : 0))
  const height = 24 + laneCount * ROW_HEIGHT

  const links = data.links.filter((link) => {
    if (showSuspiciousOnly && !link.suspicious) return false
    return nodeIndex.has(link.source) || layout.segments.some((segment) => segment.id === link.source)
  })

  return (
    <div>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-emerald-400" /> trusted
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-slate-400" /> unknown
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-amber-400" /> noncompliant
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-orange-400" /> quarantined
          </span>
          <span className="flex items-center gap-1.5">
            <span className="h-2 w-2 rounded-full bg-rose-500" /> compromised
          </span>
        </div>
        <label className="flex items-center gap-2 text-xs text-slate-400">
          <input
            type="checkbox"
            className="h-3.5 w-3.5 rounded border-white/20 bg-graphite-900 accent-cyan-400"
            checked={showSuspiciousOnly}
            onChange={(event) => setShowSuspiciousOnly(event.target.checked)}
          />
          Suspicious paths only
        </label>
      </div>

      <div className="overflow-x-auto">
        <svg
          viewBox={`0 0 ${WIDTH} ${height}`}
          className="min-w-[720px] w-full"
          role="img"
          aria-label="Authorised network segments and device relationships, with highlighted suspicious paths"
        >
          <defs>
            <pattern id="topoGrid" width="40" height="40" patternUnits="userSpaceOnUse">
              <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(148,163,184,0.07)" strokeWidth="1" />
            </pattern>
            <filter id="nodeGlow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="4" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <rect width={WIDTH} height={height} fill="url(#topoGrid)" opacity="0.5" />

          {layout.segments.map((segment) => (
            <g key={segment.id}>
              <rect
                x="12"
                y={segment.y}
                width={WIDTH - 24}
                height={segment.height}
                rx="10"
                fill="rgba(19,29,49,0.45)"
                stroke="rgba(148,163,184,0.14)"
              />
              <text x="26" y={segment.y + 22} className="fill-slate-300" style={{ fontSize: 12, fontWeight: 600 }}>
                {segment.label}
              </text>
              <text x="26" y={segment.y + 38} className="fill-slate-500 font-mono" style={{ fontSize: 10 }}>
                {segment.cidr}
              </text>
              <text x="26" y={segment.y + 54} className="fill-slate-600" style={{ fontSize: 9, letterSpacing: 1 }}>
                {segment.sensitivity?.toUpperCase()} · {segment.count} DEVICE(S)
              </text>
            </g>
          ))}

          {layout.assets.some((asset) => !asset.segmentId) && (
            <g>
              <rect
                x="12"
                y={24 + layout.segments.length * ROW_HEIGHT}
                width={WIDTH - 24}
                height={ROW_HEIGHT - 18}
                rx="10"
                fill="rgba(19,29,49,0.3)"
                stroke="rgba(148,163,184,0.1)"
                strokeDasharray="4 4"
              />
              <text
                x="26"
                y={24 + layout.segments.length * ROW_HEIGHT + 22}
                className="fill-slate-400"
                style={{ fontSize: 12 }}
              >
                Unassigned devices
              </text>
            </g>
          )}

          {links.map((link) => {
            const source = nodeIndex.get(link.source)
            const target = nodeIndex.get(link.target)
            let x1: number, y1: number, x2: number, y2: number
            if (source && target) {
              x1 = source.x
              y1 = source.y
              x2 = target.x
              y2 = target.y
            } else if (!source && target) {
              // Asset -> asset where source is external/unknown: anchor at the lane edge.
              x1 = 210
              y1 = target.y
              x2 = target.x
              y2 = target.y
            } else if (source && !target) {
              x1 = source.x
              y1 = source.y
              x2 = WIDTH - 40
              y2 = source.y
            } else {
              return null
            }
            const midX = (x1 + x2) / 2
            const path = `M ${x1} ${y1} C ${midX} ${y1}, ${midX} ${y2}, ${x2} ${y2}`
            const color = link.suspicious ? severityColor[link.severity] ?? '#f59e0b' : 'rgba(148,163,184,0.14)'
            return (
              <g key={link.id}>
                <path
                  d={path}
                  fill="none"
                  stroke={color}
                  strokeWidth={link.suspicious ? 1.6 : 1}
                  strokeOpacity={link.suspicious ? 0.8 : 0.4}
                  strokeDasharray={link.suspicious ? '5 4' : undefined}
                >
                  {link.suspicious && <title>{`${link.label} · risk ${link.risk_score}`}</title>}
                </path>
                {link.suspicious && <circle cx={x2} cy={y2} r={2.5} fill={color} />}
              </g>
            )
          })}

          {layout.assets.map((asset) => {
            const color = trustColor[asset.trust] ?? trustColor.unknown
            const isActive = activeAssetId === asset.id
            const showLabel = hovered === asset.id || isActive
            return (
              <g
                key={asset.id}
                transform={`translate(${asset.x}, ${asset.y})`}
                className="cursor-pointer"
                onClick={() => onSelectAsset?.(asset.id)}
                onMouseEnter={() => setHovered(asset.id)}
                onMouseLeave={() => setHovered(null)}
                role="button"
                tabIndex={0}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') onSelectAsset?.(asset.id)
                }}
                aria-label={`${asset.label} ${asset.ip} ${asset.trust}`}
              >
                <title>{`${asset.label} · ${asset.ip} · ${asset.trust} · criticality ${asset.criticality}/5`}</title>
                {(isActive || asset.trust === 'compromised') && (
                  <circle r={NODE_RADIUS + 5} fill="none" stroke={color} strokeOpacity="0.35" />
                )}
                <circle
                  r={NODE_RADIUS}
                  fill="#0b1220"
                  stroke={color}
                  strokeWidth={isActive ? 2.5 : 1.6}
                  filter={asset.trust === 'compromised' ? 'url(#nodeGlow)' : undefined}
                />
                <text
                  y="3.5"
                  textAnchor="middle"
                  className="fill-slate-300 font-mono"
                  style={{ fontSize: 9 }}
                >
                  {asset.label.slice(0, 2).toUpperCase()}
                </text>
                {asset.criticality >= 5 && <circle cx="9" cy="-9" r="2.5" fill="#22d3ee" />}
                {showLabel && (
                  <g>
                    <rect x="-68" y="18" width="136" height="26" rx="4" fill="rgba(7,11,18,0.95)" stroke="rgba(148,163,184,0.2)" />
                    <text x="0" y="29" textAnchor="middle" className="fill-slate-200" style={{ fontSize: 9 }}>
                      {asset.label}
                    </text>
                    <text x="0" y="39" textAnchor="middle" className="fill-slate-500 font-mono" style={{ fontSize: 8 }}>
                      {asset.ip}
                    </text>
                  </g>
                )}
              </g>
            )
          })}

          <text x={WIDTH - 16} y={height - 8} textAnchor="end" className="fill-slate-600" style={{ fontSize: 9 }}>
            {data.demo ? 'SYNTHETIC LAB TOPOLOGY' : 'LIVE INVENTORY'} · {layout.assets.length} devices
          </text>
        </svg>
      </div>

      <p className="mt-2 text-[11px] leading-relaxed text-slate-500">{data.external_note}</p>
    </div>
  )
}
