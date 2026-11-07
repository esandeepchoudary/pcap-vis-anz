import { deviceSpec } from '../lib/devices'

/** The icon for a device type, tinted by its family (see lib/devices.ts and the --dev-* tokens). */
export function DeviceIcon({ type, isPrivate = true, size = 14, label = true }: {
  type: string | null | undefined; isPrivate?: boolean; size?: number; label?: boolean
}) {
  const { icon: Icon, category } = deviceSpec(type, isPrivate)
  return <Icon size={size} className={`dev-icon dev-${category}`} aria-label={label ? type ?? 'Unknown type' : undefined} aria-hidden={!label} />
}
