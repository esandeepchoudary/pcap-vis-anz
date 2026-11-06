import { ScanSearch } from 'lucide-react'
import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { quickLook } from '../api/engagements'
import { Dropzone, ErrorNote, ProgressBar } from '../components/ui'

export function QuickLook() {
  const navigate = useNavigate()
  const [progress, setProgress] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const onFiles = async ([file]: File[]) => {
    setError(null)
    setProgress(0)
    try {
      const res = await quickLook(file, setProgress)
      navigate(`/e/${res.engagement.id}/captures/${res.capture.id}`)
    } catch (e) {
      setError((e as Error).message)
      setProgress(null)
    }
  }
  return (
    <div className="page" style={{ maxWidth: 760 }}>
      <div className="page-head">
        <div>
          <h1><ScanSearch size={24} aria-hidden style={{ verticalAlign: '-3px' }} /> Quick look</h1>
          <p>Analyse one capture without setting up an engagement. It's kept privately under "Your Quick looks" and can be turned into an engagement later.</p>
        </div>
      </div>
      <div className="stack">
        <Dropzone multiple={false} onFiles={(f) => void onFiles(f)} disabled={progress !== null}>Drop one capture file here</Dropzone>
        {progress !== null && <div className="row"><span className="muted">Uploading {Math.round(progress * 100)}%</span><div style={{ flex: 1 }}><ProgressBar value={progress} label="Upload progress" /></div></div>}
        {error && <ErrorNote>{error}</ErrorNote>}
      </div>
    </div>
  )
}
