import type { Finding } from '../api/client'

export const STATUSES: { id: Finding['status']; label: string }[] = [
  { id: 'open', label: 'Open' }, { id: 'confirmed', label: 'Confirmed' }, { id: 'accepted_risk', label: 'Accepted risk' },
  { id: 'resolved', label: 'Resolved' }, { id: 'false_positive', label: 'False positive' },
]
