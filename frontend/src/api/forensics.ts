import { useQuery } from '@tanstack/react-query'
import { api, unwrap } from './client'

export function useDashboard(eid: number) {
  return useQuery({
    queryKey: ['engagement', eid, 'dashboard'],
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/dashboard', { params: { path: { engagement_id: eid } } })),
  })
}

export function useDiff(eid: number, base: number | null, compare: number | null) {
  return useQuery({
    queryKey: ['engagement', eid, 'diff', base, compare],
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/diff', {
      params: { path: { engagement_id: eid }, query: { base: base!, compare: compare! } },
    })),
    enabled: !!base && !!compare && base !== compare,
  })
}

export function usePackets(eid: number, cid: number | null, filter: string) {
  return useQuery({
    queryKey: ['engagement', eid, 'packets', cid, filter],
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/captures/{capture_id}/packets', {
      params: { path: { engagement_id: eid, capture_id: cid! }, query: { filter, limit: 500 } },
    })),
    enabled: !!cid,
    staleTime: Infinity,
  })
}

export function usePacket(eid: number, cid: number | null, n: number | null) {
  return useQuery({
    queryKey: ['engagement', eid, 'packet', cid, n],
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/captures/{capture_id}/packets/{number}', {
      params: { path: { engagement_id: eid, capture_id: cid!, number: n! } },
    })),
    enabled: !!cid && !!n,
    staleTime: Infinity,
  })
}
