import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import {
  api, uploadForm, unwrap,
  type AnalysisResult, type Capture, type CapturePoint, type Engagement, type EngagementCreate,
  type EngagementUpdate, type MemberRole, type QuickLookResult, type UploadResult,
} from './client'

export const ekeys = {
  list: (quicklook: boolean, archived: boolean) => ['engagements', { quicklook, archived }] as const,
  all: ['engagements'] as const,
  one: (eid: number) => ['engagement', eid] as const,
  points: (eid: number) => ['engagement', eid, 'points'] as const,
  captures: (eid: number) => ['engagement', eid, 'captures'] as const,
  result: (eid: number, cid: number) => ['engagement', eid, 'result', cid] as const,
  members: (eid: number) => ['engagement', eid, 'members'] as const,
  audit: (eid: number) => ['engagement', eid, 'audit'] as const,
  directory: ['directory'] as const,
}

const p = (eid: number) => ({ params: { path: { engagement_id: eid } } })
const pc = (eid: number, cid: number) => ({ params: { path: { engagement_id: eid, capture_id: cid } } })

// ── engagements ─────────────────────────────────────────────────────────────

export function useEngagements(quicklook = false, includeArchived = false) {
  return useQuery({
    queryKey: ekeys.list(quicklook, includeArchived),
    queryFn: async () =>
      unwrap(await api.GET('/api/engagements', { params: { query: { quicklook, include_archived: includeArchived } } })),
  })
}

export function useEngagement(eid: number | null) {
  return useQuery({
    queryKey: ekeys.one(eid ?? 0),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}', p(eid as number))),
    enabled: !!eid,
  })
}

export function useCreateEngagement() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: EngagementCreate) => unwrap(await api.POST('/api/engagements', { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ekeys.all }),
  })
}

export function useUpdateEngagement(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: EngagementUpdate) => unwrap(await api.PATCH('/api/engagements/{engagement_id}', { ...p(eid), body })),
    onSuccess: (e) => {
      qc.setQueryData(ekeys.one(eid), e)
      void qc.invalidateQueries({ queryKey: ekeys.all })
    },
  })
}

export function useDeleteEngagement(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const r = await api.DELETE('/api/engagements/{engagement_id}', p(eid))
      if (!r.response.ok) unwrap(r)
    },
    onSuccess: () => {
      qc.removeQueries({ queryKey: ekeys.one(eid) })
      void qc.invalidateQueries({ queryKey: ekeys.all })
    },
  })
}

export function importEngagement(file: File, onProgress?: (f: number) => void) {
  const form = new FormData()
  form.append('file', file)
  return uploadForm<Engagement>('/api/engagements/import', form, onProgress)
}

export function exportUrl(eid: number, captures: boolean, files: boolean) {
  return `/api/engagements/${eid}/export?captures=${captures}&files=${files}`
}

// ── capture points ──────────────────────────────────────────────────────────

export function useCapturePoints(eid: number) {
  return useQuery({
    queryKey: ekeys.points(eid),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/capture-points', p(eid))),
  })
}

export function useSaveCapturePoint(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (v: { id?: number; name: string; description: string }): Promise<CapturePoint> =>
      v.id
        ? unwrap(await api.PATCH('/api/engagements/{engagement_id}/capture-points/{point_id}', {
            params: { path: { engagement_id: eid, point_id: v.id } }, body: { name: v.name, description: v.description },
          }))
        : unwrap(await api.POST('/api/engagements/{engagement_id}/capture-points', { ...p(eid), body: v })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }),
  })
}

export function useDeleteCapturePoint(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (pointId: number) => {
      const r = await api.DELETE('/api/engagements/{engagement_id}/capture-points/{point_id}', {
        params: { path: { engagement_id: eid, point_id: pointId } },
      })
      if (!r.response.ok) unwrap(r)
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }),
  })
}

// ── captures ────────────────────────────────────────────────────────────────

export function useCaptures(eid: number) {
  return useQuery({
    queryKey: ekeys.captures(eid),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/captures', p(eid))),
  })
}

export function uploadCaptures(eid: number, files: File[], pointId: number | null, onProgress?: (f: number) => void) {
  const form = new FormData()
  for (const f of files) form.append('files', f)
  if (pointId) form.append('capture_point_id', String(pointId))
  return uploadForm<UploadResult[]>(`/api/engagements/${eid}/captures`, form, onProgress)
}

export function quickLook(file: File, onProgress?: (f: number) => void) {
  const form = new FormData()
  form.append('file', file)
  return uploadForm<QuickLookResult>('/api/quicklook', form, onProgress)
}

type CaptureAction = 'cancel' | 'reanalyze' | 'delete' | { capture_point_id: number | null }

export function useCaptureAction(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ cid, action }: { cid: number; action: CaptureAction }): Promise<Capture | null> => {
      if (action === 'cancel') return unwrap(await api.POST('/api/engagements/{engagement_id}/captures/{capture_id}/cancel', pc(eid, cid)))
      if (action === 'reanalyze') return unwrap(await api.POST('/api/engagements/{engagement_id}/captures/{capture_id}/reanalyze', pc(eid, cid)))
      if (action === 'delete') {
        const r = await api.DELETE('/api/engagements/{engagement_id}/captures/{capture_id}', pc(eid, cid))
        if (!r.response.ok) unwrap(r)
        return null
      }
      return unwrap(await api.PATCH('/api/engagements/{engagement_id}/captures/{capture_id}', { ...pc(eid, cid), body: action }))
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }),
  })
}

/** ``version`` (the capture's finished_at) makes a re-analysis fetch the new result. */
export function useCaptureResult(eid: number, cid: number, enabled: boolean, version = '') {
  return useQuery({
    queryKey: [...ekeys.result(eid, cid), version],
    queryFn: async (): Promise<AnalysisResult> =>
      unwrap(await api.GET('/api/engagements/{engagement_id}/captures/{capture_id}/result', pc(eid, cid))),
    enabled,
    staleTime: Infinity, // a result never changes; re-analysis invalidates it
  })
}

export function captureDownloadUrl(eid: number, cid: number) {
  return `/api/engagements/${eid}/captures/${cid}/download`
}

export function fileDownloadUrl(eid: number, sha256: string, name: string) {
  return `/api/engagements/${eid}/files/${sha256}?name=${encodeURIComponent(name)}`
}

// ── members, directory, audit ───────────────────────────────────────────────

export function useMembers(eid: number, enabled = true) {
  return useQuery({
    queryKey: ekeys.members(eid),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/members', p(eid))),
    enabled,
  })
}

export function useDirectory(enabled: boolean) {
  return useQuery({ queryKey: ekeys.directory, queryFn: async () => unwrap(await api.GET('/api/directory')), enabled })
}

export function useSetMember(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ userId, role }: { userId: number; role: MemberRole | null }) => {
      const params = { params: { path: { engagement_id: eid, user_id: userId } } }
      if (role === null) {
        const r = await api.DELETE('/api/engagements/{engagement_id}/members/{user_id}', params)
        if (!r.response.ok) unwrap(r)
        return null
      }
      return unwrap(await api.PUT('/api/engagements/{engagement_id}/members/{user_id}', { ...params, body: { role } }))
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }),
  })
}

export function useAudit(eid: number) {
  return useQuery({
    queryKey: ekeys.audit(eid),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/audit', { ...p(eid), params: { ...p(eid).params, query: { limit: 50 } } })),
  })
}

// ── live updates ────────────────────────────────────────────────────────────

/** Refresh everything about an engagement whenever the server reports a new revision. */
export function useEngagementEvents(eid: number) {
  const qc = useQueryClient()
  useEffect(() => {
    if (typeof EventSource === 'undefined') return
    const es = new EventSource(`/api/engagements/${eid}/events`)
    let last: number | null = null
    es.addEventListener('revision', (ev) => {
      const rev = Number((ev as MessageEvent).data)
      if (last !== null && rev !== last) {
        // Results are immutable per capture; refresh lists and summaries.
        void qc.invalidateQueries({
          predicate: (q) => q.queryKey[0] === 'engagement' && q.queryKey[1] === eid && q.queryKey[2] !== 'result',
        })
        void qc.invalidateQueries({ queryKey: ekeys.all })
      }
      last = rev
    })
    return () => es.close()
  }, [eid, qc])
}
