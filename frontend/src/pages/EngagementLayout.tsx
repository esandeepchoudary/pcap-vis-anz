import { Suspense } from 'react'
import { Outlet, useParams } from 'react-router-dom'
import { ApiError } from '../api/client'
import { useEngagement, useEngagementEvents } from '../api/engagements'
import { ErrorNote } from '../components/ui'

/** Loads the engagement for /e/:eid/* and keeps it live while it's open. */
export function EngagementLayout() {
  const eid = Number(useParams().eid)
  const eng = useEngagement(eid)
  useEngagementEvents(eid)
  if (eng.isPending) return <div className="page muted">Loading…</div>
  if (eng.isError) {
    const notFound = eng.error instanceof ApiError && eng.error.status === 404
    return (
      <div className="page">
        <ErrorNote>{notFound ? "This engagement doesn't exist or you don't have access to it." : eng.error.message}</ErrorNote>
      </div>
    )
  }
  return (
    <Suspense fallback={<div className="page muted">Loading…</div>}>
      <Outlet context={eng.data} />
    </Suspense>
  )
}
