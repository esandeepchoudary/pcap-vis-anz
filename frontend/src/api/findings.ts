import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, unwrap, type FindingCreate, type FindingUpdate } from './client'

const key = (eid: number) => ['engagement', eid, 'findings'] as const

export function useFindings(eid: number) {
  return useQuery({
    queryKey: key(eid),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/findings', { params: { path: { engagement_id: eid } } })),
  })
}

export function useUpdateFinding(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ key: k, ...body }: Partial<FindingUpdate> & { key: string }) =>
      unwrap(await api.PATCH('/api/engagements/{engagement_id}/findings/{key}', {
        params: { path: { engagement_id: eid, key: k } }, body: { clear_severity_override: false, ...body },
      })),
    onSuccess: () => qc.invalidateQueries({ queryKey: key(eid) }),
  })
}

export function useCreateFinding(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: Partial<FindingCreate> & Pick<FindingCreate, 'title' | 'severity'>) =>
      unwrap(await api.POST('/api/engagements/{engagement_id}/findings', {
        params: { path: { engagement_id: eid } }, body: { description: '', recommendation: '', asset_ids: [], ...body },
      })),
    onSuccess: () => qc.invalidateQueries({ queryKey: key(eid) }),
  })
}

export function useDeleteFinding(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (k: string) => {
      const r = await api.DELETE('/api/engagements/{engagement_id}/findings/{key}', { params: { path: { engagement_id: eid, key: k } } })
      if (!r.response.ok) unwrap(r)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: key(eid) }),
  })
}

export const reportUrl = (eid: number, name: string) => `/api/engagements/${eid}/reports/${name}`
