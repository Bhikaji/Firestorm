import { Link } from 'react-router-dom'

export default function NotFoundPage() {
  return (
    <div className="panel flex flex-col items-center gap-3 p-10 text-center">
      <p className="font-mono text-3xl text-slate-600">404</p>
      <h1 className="text-sm font-semibold text-slate-200">This console view does not exist</h1>
      <p className="max-w-md text-xs leading-relaxed text-slate-500">
        The link may be outdated. Dashboards, alerts, incidents and device security are reachable from the navigation.
      </p>
      <Link to="/" className="btn mt-2">
        Return to overview
      </Link>
    </div>
  )
}
