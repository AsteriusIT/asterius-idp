import { useState, type JSX, type PointerEvent } from 'react';
import {
  ArrowDown,
  ArrowUp,
  Fingerprint,
  GripVertical,
  KeyRound,
  LockKeyhole,
  Plus,
  ShieldCheck,
  Trash2,
} from 'lucide-react';
import {
  moveAssuranceLevel,
  type AssuranceLevel,
  type AssurancePolicy,
} from './assurance-policy-model';
import { Button, Field } from './ui';

export type { AssuranceLevel, AssurancePolicy } from './assurance-policy-model';

const METHODS = [
  { value: 'pwd', label: 'Password', detail: 'Knowledge factor', Icon: LockKeyhole },
  { value: 'swk', label: 'Passkey', detail: 'Phishing-resistant', Icon: KeyRound },
  { value: 'user', label: 'User verification', detail: 'Biometric or PIN', Icon: Fingerprint },
] as const;

function displayName(level: AssuranceLevel): string {
  if (level.value === '') return 'New assurance level';
  if (level.value === 'phr') return 'Phishing-resistant';
  if (level.amr.includes('swk') && level.amr.includes('user')) return 'Verified passkey';
  if (level.amr.length === 1 && level.amr.includes('swk')) return 'Passkey';
  if (level.amr.length === 1 && level.amr.includes('pwd')) return 'Password';
  return 'Custom assurance';
}

function requirementSummary(level: AssuranceLevel): string {
  const names = METHODS.filter(({ value }) => level.amr.includes(value)).map(({ label }) => label);
  return names.length === 0 ? 'No authentication method selected' : `Requires ${names.join(' + ')}`;
}

/** The ordered, server-validated contexts a tenant advertises to applications. */
export function AssuranceEditor({ policy, onChange, disabled }: Readonly<{
  policy: AssurancePolicy;
  onChange: (value: AssurancePolicy) => void;
  disabled: boolean;
}>): JSX.Element {
  const [dragging, setDragging] = useState<number | null>(null);
  const [dropTarget, setDropTarget] = useState<number | null>(null);
  const [announcement, setAnnouncement] = useState('');

  const changeLevel = (index: number, level: AssuranceLevel): void =>
    onChange({ ...policy, levels: policy.levels.map((old, i) => i === index ? level : old) });

  const moveLevel = (from: number, to: number): void => {
    const moved = policy.levels[from];
    if (moved === undefined || from === to) return;
    onChange({ ...policy, levels: moveAssuranceLevel(policy.levels, from, to) });
    setAnnouncement(`${displayName(moved)} moved to assurance level ${to + 1}.`);
  };

  const startDrag = (event: PointerEvent<HTMLElement>, index: number): void => {
    if (disabled || event.button !== 0) return;
    event.currentTarget.setPointerCapture(event.pointerId);
    setDragging(index);
    setDropTarget(index);
  };

  const drag = (event: PointerEvent<HTMLElement>): void => {
    if (dragging === null) return;
    event.preventDefault();
    const item = document.elementFromPoint(event.clientX, event.clientY)
      ?.closest<HTMLElement>('[data-assurance-index]');
    if (item === undefined || item === null) return;
    const index = Number.parseInt(item.dataset.assuranceIndex ?? '', 10);
    if (Number.isInteger(index)) setDropTarget(index);
  };

  const finishDrag = (event: PointerEvent<HTMLElement>): void => {
    if (dragging !== null && dropTarget !== null) moveLevel(dragging, dropTarget);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    setDragging(null);
    setDropTarget(null);
  };

  return <fieldset className="settings-section assurance-editor" disabled={disabled}>
    <legend>Authentication assurance</legend>
    <p className="muted">Build the assurance flow applications can request. Levels are evaluated from weakest to strongest; drag a card or use its arrow buttons to change the order.</p>

    <label className="assurance-release-row">
      <span className="assurance-release-icon"><ShieldCheck aria-hidden="true" /></span>
      <span className="assurance-release-copy">
        <strong>Include authentication methods in ID tokens</strong>
        <span>Expose the methods used as the token's <code>amr</code> claim.</span>
      </span>
      <span className="capability-state" aria-hidden="true">{policy.amr_in_id_token ? 'Included' : 'Hidden'}</span>
      <input className="capability-switch" type="checkbox" role="switch"
        checked={policy.amr_in_id_token}
        onChange={(event) => onChange({ ...policy, amr_in_id_token: event.target.checked })} />
    </label>

    <div className="assurance-flow-heading" aria-hidden="true">
      <span>Weakest</span><span className="assurance-flow-line" /><span>Strongest</span>
    </div>
    <p id="assurance-reorder-help" className="visually-hidden">Drag assurance levels to reorder them, or focus a drag handle and press the up or down arrow key.</p>
    <p className="visually-hidden" aria-live="polite">{announcement}</p>

    <div className="assurance-flow">
      {policy.levels.map((level, index) => {
        const name = displayName(level);
        const isDragging = dragging === index;
        const isDropTarget = dropTarget === index && dragging !== index;
        return <div key={index} data-assurance-index={index}
          className={`assurance-flow-item${isDragging ? ' is-dragging' : ''}${isDropTarget ? ' is-drop-target' : ''}`}>
          <div className="assurance-node" aria-hidden="true"><span>{index + 1}</span></div>
          <article className="assurance-card" aria-labelledby={`assurance-title-${index}`}>
            <header className="assurance-card-header">
              <span role="button" className="assurance-drag-handle"
                tabIndex={disabled ? -1 : 0} aria-disabled={disabled}
                aria-label={`Reorder assurance level ${index + 1}: ${name}`}
                aria-describedby="assurance-reorder-help"
                onPointerDown={(event) => startDrag(event, index)}
                onPointerMove={drag}
                onPointerUp={finishDrag}
                onPointerCancel={() => { setDragging(null); setDropTarget(null); }}
                onKeyDown={(event) => {
                  if (disabled) return;
                  if (event.key === 'ArrowUp' && index > 0) {
                    event.preventDefault();
                    moveLevel(index, index - 1);
                  }
                  if (event.key === 'ArrowDown' && index < policy.levels.length - 1) {
                    event.preventDefault();
                    moveLevel(index, index + 1);
                  }
                }}>
                <GripVertical aria-hidden="true" />
              </span>
              <div className="assurance-card-title">
                <span className="assurance-level-label">Assurance level {index + 1}</span>
                <h3 id={`assurance-title-${index}`}>{name}</h3>
                <span className={level.amr.length === 0 ? 'assurance-requirement warning' : 'assurance-requirement'}>
                  {requirementSummary(level)}
                </span>
              </div>
              <div className="assurance-card-actions">
                <Button small variant="ghost" disabled={index === 0}
                  aria-label={`Move assurance level ${index + 1} earlier`}
                  title="Move earlier" onClick={() => moveLevel(index, index - 1)}>
                  <ArrowUp aria-hidden="true" />
                </Button>
                <Button small variant="ghost" disabled={index === policy.levels.length - 1}
                  aria-label={`Move assurance level ${index + 1} later`}
                  title="Move later" onClick={() => moveLevel(index, index + 1)}>
                  <ArrowDown aria-hidden="true" />
                </Button>
                <Button small variant="ghost"
                  aria-label={`Remove assurance level ${index + 1}: ${name}`}
                  title="Remove level"
                  onClick={() => onChange({ ...policy, levels: policy.levels.filter((_, i) => i !== index) })}>
                  <Trash2 aria-hidden="true" />
                </Button>
              </div>
            </header>

            <div className="assurance-card-body">
              <Field label="ACR value" hint="The exact ASCII identifier applications request; no spaces, maximum 255 characters.">
                {(props) => <input {...props} aria-label={`Assurance level ${index + 1} ACR value`}
                  value={level.value} maxLength={255}
                  placeholder="urn:example:acr:verified"
                  onChange={(event) => changeLevel(index, { ...level, value: event.target.value })} />}
              </Field>
              <fieldset className="assurance-methods">
                <legend>Required authentication methods</legend>
                <div className="assurance-method-grid">
                  {METHODS.map(({ value, label, detail, Icon }) => {
                    const checked = level.amr.includes(value);
                    return <label key={value} className={checked ? 'assurance-method selected' : 'assurance-method'}>
                      <input type="checkbox" checked={checked}
                        aria-label={`Assurance level ${index + 1}: ${label}`}
                        onChange={(event) => changeLevel(index, {
                          ...level,
                          amr: event.target.checked
                            ? [...level.amr, value]
                            : level.amr.filter((old) => old !== value),
                        })} />
                      <span className="assurance-method-icon"><Icon aria-hidden="true" /></span>
                      <span><strong>{label}</strong><small>{detail}</small></span>
                    </label>;
                  })}
                </div>
              </fieldset>
            </div>
          </article>
        </div>;
      })}
    </div>

    {policy.levels.length === 0 && <div className="assurance-empty">
      <ShieldCheck aria-hidden="true" />
      <strong>No authentication contexts</strong>
      <span>No ACR values will be advertised or included in newly issued tokens.</span>
    </div>}

    <Button className="assurance-add" disabled={policy.levels.length >= 32} onClick={() => onChange({
      ...policy, levels: [...policy.levels, { value: '', amr: ['swk', 'user'] }],
    })}><Plus aria-hidden="true" /> Add assurance level</Button>
    <p className="assurance-footnote">Changes reach new requests across servers within 30 seconds. Existing sessions must still prove every required method; administrator passkey verification is always enforced.</p>
  </fieldset>;
}
