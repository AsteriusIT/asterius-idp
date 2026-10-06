import { useState, type JSX, type ReactNode } from 'react';
import { InlineSwitch } from './inline-switch';
import { CopyIcon, FileCodeIcon } from 'lucide-react';
import { Badge, Button } from '../ui';
import { toast } from './ui/toast';

/** Read-only source: gutter text is decorative and never enters copied content. */
export function CodePanel({ source, label, language, renderLine }: Readonly<{
  source: string;
  label: string;
  language: 'JSON' | 'YAML';
  renderLine: (line: string) => ReactNode;
}>): JSX.Element {
  const [wrap, setWrap] = useState(true);
  const lines = source.split('\n');
  const trailingNewline = source.endsWith('\n');
  if (trailingNewline) lines.pop();
  const copy = async (): Promise<void> => {
    try {
      await navigator.clipboard.writeText(source);
      toast.success(`${language} copied`);
    } catch {
      toast.error(`Could not copy the ${language}`);
    }
  };
  return <div className="code-panel" data-wrap={wrap}>
    <div className="code-panel-toolbar">
      <div className="code-panel-heading"><FileCodeIcon aria-hidden="true" /><span className="code-panel-label">{label}</span><Badge>{language}</Badge><span className="code-panel-count">{lines.length} {lines.length === 1 ? 'line' : 'lines'}</span></div>
      <div className="code-panel-actions"><InlineSwitch label="Wrap lines" accessibleLabel={`Wrap lines in ${label}`} checked={wrap} onCheckedChange={setWrap} /><Button small onClick={() => void copy()} aria-label={`Copy ${label}`}><CopyIcon data-icon="inline-start" aria-hidden="true" />Copy</Button></div>
    </div>
    <pre className="code-panel-source" tabIndex={0} role="region" aria-label={label}><code>{lines.map((line, index) => <span className="code-panel-line" key={index}>
      <span className="code-panel-gutter" aria-hidden="true" data-line={index + 1} /><span className="code-panel-content">{renderLine(line)}{index < lines.length - 1 || trailingNewline ? '\n' : ''}</span>
    </span>)}</code></pre>
  </div>;
}
