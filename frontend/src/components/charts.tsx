import { useMemo } from 'react'

/**
 * Hand-built SVG charts: no charting dependency, no animation loops, accessible
 * descriptions. Every series is read from real API data - nothing is randomised.
 */

const severityColor: Record<string, string> = {
  critical: '#f43f5e',
  high: '#fb923c',
  medium: '#f59e0b',
  low: '#38bdf8',
  info: '#64748b',
}

export function SeverityBars({ data }: { data: Array<{ severity: string; count: number }> }) {
  const max = Math.max(1, ...data.map((item) => item.count))
  return (
    <div className="space-y-3" role="img" aria-label="Alert counts by severity">
      {data.map((item) => (
        <div key={item.severity} className="flex items-center gap-3">
          <span className="w-16 text-[11px] uppercase tracking-wider text-slate-500">{item.severity}</span>
          <div className="h-2 flex-1 overflow-hidden rounded-full bg-white/[0.06]">
            <div
              className="h-full rounded-full transition-[width] duration-300"
              style={{
                width: `${(item.count / max) * 100}%`,
                backgroundColor: severityColor[item.severity] ?? '#64748b',
              }}
            />
          </div>
          <span className="w-8 text-right font-mono text-xs tabular-nums text-slate-300">{item.count}</span>
        </div>
      ))}
    </div>
  )
}

export function TrendChart({ data }: { data: Array<Record<string, string | number>> }) {
  const series = ['critical', 'high', 'medium', 'low']
  const width = 640
  const height = 160
  const padding = { top: 10, right: 8, bottom: 20, left: 8 }

  const points = useMemo(() => {
    if (data.length === 0) return []
    const totals = data.map((row) => series.reduce((sum, key) => sum + Number(row[key] ?? 0), 0))
    const max = Math.max(1, ...totals)
    return data.map((row, index) => {
      const x = padding.left + (index / Math.max(1, data.length - 1)) * (width - padding.left - padding.right)
      const y = height - padding.bottom - (Number(row.high ?? 0) / max) * (height - padding.top - padding.bottom)
      return { x, y, row, total: totals[index], max }
    })
  }, [data])

  if (data.length === 0) {
    return <p className="py-10 text-center text-xs text-slate-500">No alerts in this window.</p>
  }

  const path = points.map((point, index) => `${index === 0 ? 'M' : 'L'}${point.x},${point.y}`).join(' ')
  const area = `${path} L${points[points.length - 1].x},${height - padding.bottom} L${points[0].x},${height - padding.bottom} Z`

  return (
    <div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-40 w-full"
        role="img"
        aria-label="High-severity alerts per day trend"
      >
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#22d3ee" stopOpacity="0.28" />
            <stop offset="100%" stopColor="#22d3ee" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((fraction) => (
          <line
            key={fraction}
            x1={padding.left}
            x2={width - padding.right}
            y1={padding.top + fraction * (height - padding.top - padding.bottom)}
            y2={padding.top + fraction * (height - padding.top - padding.bottom)}
            stroke="rgba(148,163,184,0.12)"
            strokeDasharray="3 6"
          />
        ))}
        <path d={area} fill="url(#trendFill)" />
        <path d={path} fill="none" stroke="#22d3ee" strokeWidth="1.75" strokeLinejoin="round" />
        {points.map((point, index) => (
          <circle key={index} cx={point.x} cy={point.y} r={2.5} fill="#0b1220" stroke="#22d3ee" strokeWidth="1.5">
            <title>
              {String(point.row.date)} — {point.total} alerts
            </title>
          </circle>
        ))}
      </svg>
      <div className="flex justify-between px-1 text-[10px] text-slate-600">
        <span>{String(data[0].date ?? '')}</span>
        <span>{String(data[data.length - 1].date ?? '')}</span>
      </div>
    </div>
  )
}

export function TrustDonut({ data }: { data: Array<{ state: string; count: number }> }) {
  const total = data.reduce((sum, item) => sum + item.count, 0)
  const colors: Record<string, string> = {
    trusted: '#34d399',
    unknown: '#64748b',
    noncompliant: '#f59e0b',
    quarantined: '#fb923c',
    compromised: '#f43f5e',
  }
  let offset = 0
  const radius = 54
  const circumference = 2 * Math.PI * radius

  return (
    <div className="flex flex-wrap items-center gap-6">
      <svg viewBox="0 0 140 140" className="h-36 w-36 -rotate-90" role="img" aria-label="Device trust distribution">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth="14" />
        {data.map((item) => {
          const length = total > 0 ? (item.count / total) * circumference : 0
          const circle = (
            <circle
              key={item.state}
              cx="70"
              cy="70"
              r={radius}
              fill="none"
              stroke={colors[item.state] ?? '#475569'}
              strokeWidth="14"
              strokeDasharray={`${length} ${circumference - length}`}
              strokeDashoffset={-offset}
              strokeLinecap="butt"
            />
          )
          offset += length
          return circle
        })}
      </svg>
      <ul className="flex-1 space-y-2 text-xs">
        {data.map((item) => (
          <li key={item.state} className="flex items-center justify-between gap-3">
            <span className="flex items-center gap-2 capitalize text-slate-400">
              <span
                className="h-2 w-2 rounded-full"
                style={{ backgroundColor: colors[item.state] ?? '#475569' }}
                aria-hidden
              />
              {item.state}
            </span>
            <span className="font-mono tabular-nums text-slate-300">{item.count}</span>
          </li>
        ))}
        <li className="flex items-center justify-between gap-3 border-t border-white/[0.06] pt-2 text-slate-500">
          <span>Total assets</span>
          <span className="font-mono tabular-nums">{total}</span>
        </li>
      </ul>
    </div>
  )
}

export function PostureRing({ score, label }: { score: number; label: string }) {
  const radius = 52
  const circumference = 2 * Math.PI * radius
  const dash = (Math.min(100, Math.max(0, score)) / 100) * circumference
  const color = score >= 80 ? '#34d399' : score >= 60 ? '#22d3ee' : score >= 40 ? '#f59e0b' : '#f43f5e'
  return (
    <div className="flex items-center gap-4">
      <svg viewBox="0 0 140 140" className="h-32 w-32" role="img" aria-label={`Overall security posture ${score} of 100`}>
        <circle cx="70" cy="70" r={radius} fill="none" stroke="rgba(148,163,184,0.12)" strokeWidth="10" />
        <circle
          cx="70"
          cy="70"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference - dash}`}
          transform="rotate(-90 70 70)"
        />
        <text x="70" y="72" textAnchor="middle" className="fill-slate-100 font-mono" style={{ fontSize: 26 }}>
          {score}
        </text>
        <text x="70" y="90" textAnchor="middle" className="fill-slate-500" style={{ fontSize: 9, letterSpacing: 1.4 }}>
          POSTURE
        </text>
      </svg>
      <div>
        <p className="text-sm font-medium" style={{ color }}>
          {label}
        </p>
        <p className="mt-1 max-w-[220px] text-xs leading-relaxed text-slate-500">
          Share of inventoried devices that are enrolled, enrolled-compliant and reporting current posture.
        </p>
      </div>
    </div>
  )
}

export function Sparkline({ values, tone = '#22d3ee' }: { values: number[]; tone?: string }) {
  if (values.length < 2) return <div className="h-6" />
  const max = Math.max(...values, 1)
  const min = Math.min(...values, 0)
  const points = values
    .map((value, index) => {
      const x = (index / (values.length - 1)) * 100
      const y = 24 - ((value - min) / Math.max(1, max - min)) * 20
      return `${x},${y}`
    })
    .join(' ')
  return (
    <svg viewBox="0 0 100 26" preserveAspectRatio="none" className="h-6 w-full" aria-hidden>
      <polyline points={points} fill="none" stroke={tone} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
    </svg>
  )
}
