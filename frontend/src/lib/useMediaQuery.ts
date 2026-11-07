import { useSyncExternalStore } from 'react'

/** Live result of a CSS media query (false where matchMedia is unavailable, e.g. some test environments). */
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (typeof window.matchMedia !== 'function') return () => {}
      const mq = window.matchMedia(query)
      mq.addEventListener('change', onChange)
      return () => mq.removeEventListener('change', onChange)
    },
    () => typeof window.matchMedia === 'function' && window.matchMedia(query).matches,
  )
}

/** Below this width the inspector is a drawer over the page instead of a column. */
export const NARROW = '(max-width: 1100px)'
