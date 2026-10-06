import { TabsList, TabsTrigger } from './ui/tabs';

/** ReUI's numbered title/description pattern on the existing Base Tabs controller.
 * Position is navigation only, never proof that a step is valid or saved. */
export function WorkflowSteps({ steps, label }: { label: string; steps: readonly { value: string; title: string; description: string }[] }) {
  return <TabsList className="application-tabs workflow-steps" aria-label={label}>
    {steps.map((step, index) => <TabsTrigger key={step.value} value={step.value} aria-label={step.title}>
      <span className="workflow-step-number" aria-hidden="true">{index + 1}</span>
      <span className="workflow-step-copy"><strong>{step.title}</strong><span>{step.description}</span></span>
    </TabsTrigger>)}
  </TabsList>;
}
