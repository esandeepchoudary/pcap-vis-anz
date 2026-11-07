import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import {
  api, unwrap,
  type AssetBulkEdit, type AssetCreate, type AssetDetail, type AssetEdit,
} from './client'

export const akeys = {
  all: (eid: number) => ['engagement', eid, 'assets'] as const,
  one: (eid: number, id: number) => ['engagement', eid, 'assets', id] as const,
  history: (eid: number, id: number) => ['engagement', eid, 'assets', id, 'history'] as const,
  fields: ['asset-fields'] as const,
}

const pa = (eid: number, id: number) => ({ params: { path: { engagement_id: eid, asset_id: id } } })

export function useAssetFields() {
  return useQuery({
    queryKey: akeys.fields,
    queryFn: async () => unwrap(await api.GET('/api/asset-fields')),
    staleTime: Infinity,
  })
}

export function useAssets(eid: number) {
  return useQuery({
    queryKey: akeys.all(eid),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/assets', { params: { path: { engagement_id: eid } } })),
  })
}

export function useAsset(eid: number, id: number) {
  return useQuery({
    queryKey: akeys.one(eid, id),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/assets/{asset_id}', pa(eid, id))),
  })
}

export function useAssetHistory(eid: number, id: number, enabled = true) {
  return useQuery({
    queryKey: akeys.history(eid, id),
    queryFn: async () => unwrap(await api.GET('/api/engagements/{engagement_id}/assets/{asset_id}/history', pa(eid, id))),
    enabled,
  })
}

export function useEditAsset(eid: number, id: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: AssetEdit) =>
      unwrap(await api.PATCH('/api/engagements/{engagement_id}/assets/{asset_id}', { ...pa(eid, id), body })),
    onSuccess: (d: AssetDetail) => {
      qc.setQueryData(akeys.one(eid, id), d)
      void qc.invalidateQueries({ queryKey: akeys.all(eid), exact: true })
      void qc.invalidateQueries({ queryKey: akeys.history(eid, id) })
    },
  })
}

export function useBulkEdit(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: AssetBulkEdit) =>
      unwrap(await api.POST('/api/engagements/{engagement_id}/assets/bulk', { params: { path: { engagement_id: eid } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: akeys.all(eid) }),
  })
}

export function useCreateAsset(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: AssetCreate) =>
      unwrap(await api.POST('/api/engagements/{engagement_id}/assets', { params: { path: { engagement_id: eid } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: akeys.all(eid) }),
  })
}

export function useDeleteAsset(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (id: number) => {
      const r = await api.DELETE('/api/engagements/{engagement_id}/assets/{asset_id}', pa(eid, id))
      if (!r.response.ok) unwrap(r)
    },
    onSuccess: (_d, id) => {
      qc.removeQueries({ queryKey: akeys.one(eid, id) })
      void qc.invalidateQueries({ queryKey: akeys.all(eid), exact: true })
    },
  })
}

export function assetExportUrl(eid: number) {
  return `/api/engagements/${eid}/assets/export`
}

/** Merge and split move traffic and findings too: refresh everything about the engagement. */
export function useMergeAssets(eid: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ target, ...body }: { target: number; version: number; source_ids: number[]; reason: string }) =>
      unwrap(await api.POST('/api/engagements/{engagement_id}/assets/{asset_id}/merge', { ...pa(eid, target), body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }),
  })
}

export function useSplitAsset(eid: number, id: number) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { version: number; ips: string[]; reason: string }) =>
      unwrap(await api.POST('/api/engagements/{engagement_id}/assets/{asset_id}/split', { ...pa(eid, id), body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['engagement', eid] }),
  })
}
