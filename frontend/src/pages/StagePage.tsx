import type { Stage } from '../stages'

/** Placeholder for stages that arrive in later milestones. */
export function StagePage({ stage }: { stage: Stage }) {
  const Icon = stage.icon
  return (
    <div className="coming">
      <div className="icon-wrap"><Icon size={30} strokeWidth={1.7} aria-hidden /></div>
      <h1>{stage.title}</h1>
      <p>{stage.summary}</p>
      <span className="badge badge-accent">Arrives in {stage.milestone}</span>
      {stage.plans.length > 0 && (
        <ul>
          {stage.plans.map((p) => <li key={p}>{p}</li>)}
        </ul>
      )}
    </div>
  )
}
