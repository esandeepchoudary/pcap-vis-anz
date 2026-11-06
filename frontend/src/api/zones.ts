import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type ZoneIn, type ZoneUpdate } from './client'

const p = (eid: number) => ({ params: { path: { engagement_id: eid } } })
const key = (eid: number, what: string) => ['engagement', eid, what] as const

export function useZones(eid: number) {
  return useQuery({ queryKey: key(eid, 'zones'), queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/zones', p(eid))) })
}
export function useConduits(eid: number) {
  return useQuery({ queryKey: key(eid, 'conduits'), queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/conduits', p(eid))) })
}
export function useViolations(eid: number) {
  return useQuery({ queryKey: key(eid, 'violations'), queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/violations', p(eid))) })
}
export function useNetworks(eid: number) {
  return useQuery({ queryKey: key(eid, 'networks'), queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/networks', p(eid))) })
}

/** Every zone/conduit change can move assets, so refresh the whole engagement. */
function useEngagementMutation<T, R>(eid: number, fn: (v: T) => Promise<R>) {
  const qc = useQueryClient()
  return useMutation({ mutationFn: fn, onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }) })
}

export function useCreateZone(eid: number) {
  return useEngagementMutation(eid, async (body: ZoneIn) => unwrap(await api.POST('/api/engagements/{engagement_id}/zones', { ...p(eid), body })))
}
export function useUpdateZone(eid: number) {
  return useEngagementMutation(eid, async ({ id, ...body }: ZoneUpdate & { id: number }) =>
    unwrap(await api.PATCH('/api/engagements/{engagement_id}/zones/{zone_id}', { params: { path: { engagement_id: eid, zone_id: id } }, body })))
}
export function useDeleteZone(eid: number) {
  return useEngagementMutation(eid, async (id: number) => {
    const r = await api.DELETE('/api/engagements/{engagement_id}/zones/{zone_id}', { params: { path: { engagement_id: eid, zone_id: id } } })
    if (!r.response.ok) unwrap(r)
  })
}
export function useCreateConduit(eid: number) {
  return useEngagementMutation(eid, async (body: { zone_a_id: number; zone_b_id: number; allowed?: string[]; name?: string }) =>
    unwrap(await api.POST('/api/engagements/{engagement_id}/conduits', { ...p(eid), body: { name: '', description: '', ...body } })))
}
export function useUpdateConduit(eid: number) {
  return useEngagementMutation(eid, async ({ id, ...body }: { id: number; allowed?: string[]; name?: string; description?: string }) =>
    unwrap(await api.PATCH('/api/engagements/{engagement_id}/conduits/{conduit_id}', { params: { path: { engagement_id: eid, conduit_id: id } }, body })))
}
export function useDeleteConduit(eid: number) {
  return useEngagementMutation(eid, async (id: number) => {
    const r = await api.DELETE('/api/engagements/{engagement_id}/conduits/{conduit_id}', { params: { path: { engagement_id: eid, conduit_id: id } } })
    if (!r.response.ok) unwrap(r)
  })
}
