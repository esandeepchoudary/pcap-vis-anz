import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, unwrap, type UserCreate, type UserUpdate } from './client'

export const keys = {
  system: ['system'] as const,
  me: ['me'] as const,
  users: ['users'] as const,
}

export function useSystem() {
  return useQuery({
    queryKey: keys.system,
    queryFn: async () => unwrap(await api.GET('/api/system')),
    staleTime: 60_000,
  })
}

export function useMe(enabled = true) {
  return useQuery({
    queryKey: keys.me,
    queryFn: async () => unwrap(await api.GET('/api/auth/me')),
    enabled,
    retry: (count, err) => !(err instanceof ApiError && err.status === 401) && count < 2,
  })
}

export function useLogin() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: { username: string; password: string }) =>
      unwrap(await api.POST('/api/auth/login', { body })),
    onSuccess: (user) => qc.setQueryData(keys.me, user),
  })
}

export function useLogout() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async () => {
      const { response } = await api.POST('/api/auth/logout')
      if (!response.ok) throw new ApiError(response.status, 'Sign-out failed')
    },
    // Reset (not just clear) so mounted queries refetch: "me" then 401s and the sign-in page shows.
    onSettled: () => qc.resetQueries(),
  })
}

export function useChangePassword() {
  return useMutation({
    mutationFn: async (body: { current_password: string; new_password: string }) => {
      const r = await api.POST('/api/auth/password', { body })
      if (!r.response.ok) unwrap(r)
    },
  })
}

export function useUsers(enabled = true) {
  return useQuery({
    queryKey: keys.users,
    queryFn: async () => unwrap(await api.GET('/api/users')),
    enabled,
  })
}

export function useCreateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async (body: UserCreate) => unwrap(await api.POST('/api/users', { body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.users }),
  })
}

export function useUpdateUser() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, body }: { id: number; body: UserUpdate }) =>
      unwrap(await api.PATCH('/api/users/{user_id}', { params: { path: { user_id: id } }, body })),
    onSuccess: () => qc.invalidateQueries({ queryKey: keys.users }),
  })
}
