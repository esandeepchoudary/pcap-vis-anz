export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const
export type Severity = (typeof SEVERITIES)[number]
