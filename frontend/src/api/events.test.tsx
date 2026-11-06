import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import { useEngagementEvents } from './engagements'

class FakeEventSource {
  static last: FakeEventSource | null = null
  listeners: Record<string, (e: MessageEvent) => void> = {}
  closed = false
  url: string
  constructor(url: string) {
    this.url = url
    FakeEventSource.last = this
  }
  addEventListener(type: string, fn: (e: MessageEvent) => void) { this.listeners[type] = fn }
  close() { this.closed = true }
  emit(type: string, data: string) { this.listeners[type]?.({ data } as MessageEvent) }
}

function Probe({ eid }: { eid: number }) {
  useEngagementEvents(eid)
  return null
}

describe('live engagement updates', () => {
  it('invalidates engagement queries (not results) when the revision changes', () => {
    vi.stubGlobal('EventSource', FakeEventSource)
    const qc = new QueryClient()
    const spy = vi.spyOn(qc, 'invalidateQueries')
    const { unmount } = render(<QueryClientProvider client={qc}><Probe eid={7} /></QueryClientProvider>)
    const es = FakeEventSource.last!
    expect(es.url).toBe('/api/engagements/7/events')
    es.emit('revision', '5')
    expect(spy).not.toHaveBeenCalled() // first event is the baseline
    es.emit('revision', '5')
    expect(spy).not.toHaveBeenCalled() // unchanged
    es.emit('revision', '6')
    expect(spy).toHaveBeenCalledTimes(2)
    const predicate = (spy.mock.calls[0][0] as unknown as { predicate: (q: { queryKey: unknown[] }) => boolean }).predicate
    expect(predicate({ queryKey: ['engagement', 7, 'captures'] })).toBe(true)
    expect(predicate({ queryKey: ['engagement', 7, 'result', 11, 'x'] })).toBe(false)
    expect(predicate({ queryKey: ['engagement', 8, 'captures'] })).toBe(false)
    unmount()
    expect(es.closed).toBe(true)
  })
})
