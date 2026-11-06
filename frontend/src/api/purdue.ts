import { useQuery } from '@tanstack/react-query'
import { api, unwrap } from './client'

const p = (eid: number) => ({ params: { path: { engagement_id: eid } } })

/** Asset-to-asset traffic merged across captures. Refreshed by live updates (key under 'engagement'). */
export function useLinks(eid: number) {
  return useQuery({
    queryKey: ['engagement', eid, 'links'],
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/links', p(eid))),
  })
}

export function useOtOperations(eid: number) {
  return useQuery({
    queryKey: ['engagement', eid, 'ot-operations'],
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/ot-operations', p(eid))),
  })
}
