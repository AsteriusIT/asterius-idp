/** Tenant branding editor and CSP-safe, console-isolated local preview. */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { JSX } from 'react';
import { ImageIcon } from 'lucide-react';
import { mutate, read, upload, type Session } from './api';
import {
  documentOf,
  draftOf,
  isDirty,
  refusalField,
  validateDraft,
  validateLogo,
  type AssetReference,
  type BrandingDraft,
  type BrandingErrors,
  type ThemeDocument,
  type ThemeEnvelope,
  type ThemeSchema,
} from './branding-model';
import { toast } from './components/ui/toast';
import { Actions, Button, ConfirmDialog, Field, LoadFailure, Message, Panel, Screen, Skeleton } from './ui';

type Load =
  | { readonly kind: 'loading' }
  | { readonly kind: 'ready'; readonly theme: ThemeDocument; readonly schema: ThemeSchema }
  | { readonly kind: 'failed'; readonly message: string };

interface LogoUpload {
  readonly digest: string;
  readonly content_type: string;
}

const PALETTE_FIELDS = [
  ['background', 'Page background'], ['text', 'Body text'], ['muted_text', 'Secondary text'],
  ['accent', 'Primary action'], ['accent_text', 'Primary action text'], ['danger', 'Error text'],
] as const;

const FONT_LABELS: Readonly<Record<string, string>> = {
  geist: 'Geist', 'system-sans': 'System sans-serif', 'system-serif': 'System serif', 'system-mono': 'System monospace',
};

function assetPath(asset: AssetReference): string {
  return `../assets/theme/${asset.digest}`;
}

export function Branding({ session }: Readonly<{ session: Session }>): JSX.Element {
  const [load, setLoad] = useState<Load>({ kind: 'loading' });
  const [draft, setDraft] = useState<BrandingDraft | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [refusal, setRefusal] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<BrandingErrors>({});
  const [busy, setBusy] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [logoFile, setLogoFile] = useState<File | null>(null);
  const [logoPreview, setLogoPreview] = useState<string | null>(null);
  const preview = useRef<HTMLDivElement>(null);
  const canWrite = session.scopes.includes('admin.theme:write');

  const refresh = useCallback(() => {
    setLoad({ kind: 'loading' });
    setNotice(null);
    setRefusal(null);
    setServerErrors({});
    setLogoFile(null);
    setLogoPreview(null);
    read('theme').then(
      (value) => {
        const envelope = value as ThemeEnvelope;
        setLoad({ kind: 'ready', theme: envelope.theme, schema: envelope.schema });
        setDraft(draftOf(envelope.theme));
      },
      (error: unknown) => setLoad({ kind: 'failed', message: error instanceof Error ? error.message : 'the branding could not be read' }),
    );
  }, []);

  useEffect(refresh, [refresh]);
  const dirty = load.kind === 'ready' && draft !== null && (isDirty(load.theme, draft) || logoFile !== null);
  useEffect(() => {
    if (!dirty) return undefined;
    const warn = (event: BeforeUnloadEvent): void => event.preventDefault();
    window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  useEffect(() => {
    if (draft === null || preview.current === null) return;
    const node = preview.current;
    for (const [name, value] of Object.entries(draft.palette)) node.style.setProperty(`--preview-${name.replace('_', '-')}`, value);
    node.style.setProperty('--preview-radius', `${draft.radius || 0}px`);
    node.style.setProperty('--preview-space', `${draft.spacing || 8}px`);
    const fonts: Readonly<Record<string, string>> = {
      geist: 'Geist, system-ui, sans-serif', 'system-sans': 'system-ui, sans-serif',
      'system-serif': 'Georgia, serif', 'system-mono': 'ui-monospace, monospace',
    };
    node.style.setProperty('--preview-font', fonts[draft.font] ?? fonts.geist ?? 'system-ui');
  }, [draft]);

  const errors = useMemo(() => load.kind === 'ready' && draft !== null
    ? { ...validateDraft(draft, load.schema), ...serverErrors }
    : serverErrors, [draft, load, serverErrors]);

  const change = <K extends keyof BrandingDraft>(key: K, value: BrandingDraft[K]): void => {
    if (draft === null) return;
    setDraft({ ...draft, [key]: value });
    setNotice(null);
    setRefusal(null);
    setServerErrors({});
  };
  const colour = (name: keyof ThemeDocument['palette'], value: string): void => {
    if (draft !== null) change('palette', { ...draft.palette, [name]: value });
  };

  const save = (): void => {
    if (load.kind !== 'ready' || draft === null) return;
    const localErrors = validateDraft(draft, load.schema);
    if (Object.keys(localErrors).length > 0) {
      setServerErrors(localErrors);
      setRefusal('Fix the highlighted fields before saving.');
      return;
    }
    setBusy(true);
    setNotice(null);
    setRefusal(null);
    setServerErrors({});
    mutate('theme', 'PUT', session, documentOf(draft)).then(
      (value) => {
        const saved = value as ThemeDocument;
        setLoad({ kind: 'ready', theme: saved, schema: load.schema });
        setDraft(draftOf(saved));
        setNotice('Saved. The preview now shows the effective server model.');
        toast.success('Branding saved');
        setBusy(false);
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : 'the branding change was refused';
        const field = refusalField(message);
        setRefusal(message);
        setServerErrors(field === null ? {} : { [field]: 'This is the field the server refused.' });
        setBusy(false);
      },
    );
  };

  const chooseLogo = (file: File | undefined): void => {
    if (file === undefined) return;
    const error = validateLogo(file);
    if (error !== null) {
      setLogoFile(null);
      setLogoPreview(null);
      setServerErrors({ logo: error });
      return;
    }
    const reader = new FileReader();
    reader.addEventListener('load', () => setLogoPreview(typeof reader.result === 'string' ? reader.result : null), { once: true });
    reader.readAsDataURL(file);
    setLogoFile(file);
    setServerErrors({});
    setNotice(null);
  };

  const uploadLogo = (): void => {
    if (logoFile === null || draft === null || load.kind !== 'ready') return;
    setBusy(true);
    setRefusal(null);
    upload('theme/logo', session, logoFile).then(
      (value) => {
        const uploaded = value as LogoUpload;
        const logo = { digest: uploaded.digest, content_type: uploaded.content_type };
        const saved = { ...load.theme, logo };
        setLoad({ kind: 'ready', theme: saved, schema: load.schema });
        setDraft({ ...draft, logo });
        setLogoFile(null);
        setLogoPreview(null);
        setNotice('Logo uploaded. Other unsaved fields are still in the editor.');
        toast.success('Logo uploaded');
        setBusy(false);
      },
      (error: unknown) => {
        const message = error instanceof Error ? error.message : 'the logo was refused';
        setRefusal(message);
        setServerErrors({ logo: message });
        setBusy(false);
      },
    );
  };

  const reset = (): void => {
    if (load.kind !== 'ready') return;
    setBusy(true);
    mutate('theme', 'DELETE', session).then(
      (value) => {
        const saved = value as ThemeDocument;
        setLoad({ kind: 'ready', theme: saved, schema: load.schema });
        setDraft(draftOf(saved));
        setResetting(false);
        setLogoFile(null);
        setLogoPreview(null);
        setRefusal(null);
        setServerErrors({});
        setNotice('Branding reset to the shipped defaults.');
        toast.success('Branding reset');
        setBusy(false);
      },
      (error: unknown) => {
        setResetting(false);
        setRefusal(error instanceof Error ? error.message : 'the reset was refused');
        setBusy(false);
      },
    );
  };

  if (load.kind === 'loading') return <Screen title="Branding"><Panel title="Reading"><Skeleton rows={6} label="Reading the branding." /></Panel></Screen>;
  if (load.kind === 'failed') return <Screen title="Branding"><Panel title="The branding could not be read"><LoadFailure message={load.message} onRetry={refresh} /></Panel></Screen>;
  if (draft === null) return <Skeleton rows={6} label="Reading the branding." />;

  const fontOptions = load.schema.properties?.font?.enum?.filter((value): value is string => typeof value === 'string') ?? ['geist', 'system-sans', 'system-serif', 'system-mono'];
  const previewLogo = logoPreview ?? (draft.logo === undefined ? null : assetPath(draft.logo));
  const previewErrors = validateDraft(draft, load.schema);
  const links = [
    ['Help', draft.helpUrl, 'helpUrl'], ['Privacy', draft.privacyUrl, 'privacyUrl'], ['Terms', draft.termsUrl, 'termsUrl'],
  ] as const;
  const safeLinks = links.filter(([, url, field]) => url !== '' && previewErrors[field] === undefined);

  return (
    <Screen title="Branding" description="Shape the sign-in experience without changing the administration console.">
      {!canWrite && <Message tone="info">You can preview the saved branding, but your session cannot change it.</Message>}
      {dirty && <Message tone="info">You have unsaved changes.</Message>}
      {notice !== null && <Message tone="success">{notice}</Message>}
      {refusal !== null && <Message tone="error">{refusal}</Message>}
      <div className="branding-layout">
        <form className="branding-editor" noValidate onSubmit={(event) => { event.preventDefault(); save(); }}>
          <Panel title="Identity" description="The name and mark people see before they sign in.">
            <Field label="Product name" hint="Leave blank to use the tenant display name." error={errors.productName ?? null}>
              {(props) => <input {...props} maxLength={load.schema.properties?.product_name?.maxLength ?? 64} value={draft.productName} disabled={!canWrite || busy} onChange={(event) => change('productName', event.target.value)} />}
            </Field>
            <Field label="Logo" hint="PNG, JPEG or WebP; at most 200 KiB. The server decodes and sanitises it." error={errors.logo ?? null}>
              {(props) => <input {...props} type="file" accept="image/png,image/jpeg,image/webp" disabled={!canWrite || busy} onChange={(event) => chooseLogo(event.target.files?.[0])} />}
            </Field>
            {logoFile !== null && <Button onClick={uploadLogo} disabled={busy}>Upload selected logo</Button>}
          </Panel>
          <Panel title="Palette" description="Every text pair must meet accessible contrast on the sign-in page.">
            <div className="branding-palette">
              {PALETTE_FIELDS.map(([name, label]) => <Field key={name} label={label} error={errors[name] ?? null}>
                {(props) => <div className="colour-control"><input aria-label={`${label} picker`} type="color" value={/^#[0-9a-fA-F]{6}$/.test(draft.palette[name]) ? draft.palette[name] : '#000000'} disabled={!canWrite || busy} onChange={(event) => colour(name, event.target.value)} /><input {...props} value={draft.palette[name]} disabled={!canWrite || busy} onChange={(event) => colour(name, event.target.value)} /></div>}
              </Field>)}
            </div>
          </Panel>
          <Panel title="Layout" description="Use only fonts shipped by this server.">
            <Field label="Font" error={errors.font ?? null}>{(props) => <select {...props} value={draft.font} disabled={!canWrite || busy} onChange={(event) => change('font', event.target.value)}>{fontOptions.map((font) => <option key={font} value={font}>{FONT_LABELS[font] ?? font}</option>)}</select>}</Field>
            <div className="branding-scale">
              <Field label="Corner radius (px)" error={errors.radius ?? null}>{(props) => <input {...props} type="number" min={0} max={24} value={draft.radius} disabled={!canWrite || busy} onChange={(event) => change('radius', event.target.value)} />}</Field>
              <Field label="Spacing (px)" error={errors.spacing ?? null}>{(props) => <input {...props} type="number" min={4} max={16} value={draft.spacing} disabled={!canWrite || busy} onChange={(event) => change('spacing', event.target.value)} />}</Field>
            </div>
          </Panel>
          <Panel title="Support links" description="Optional HTTPS destinations shown beneath the sign-in card.">
            {([['Help URL', 'helpUrl'], ['Privacy URL', 'privacyUrl'], ['Terms URL', 'termsUrl']] as const).map(([label, field]) => <Field key={field} label={label} error={errors[field] ?? null}>{(props) => <input {...props} type="url" placeholder="https://" value={draft[field]} disabled={!canWrite || busy} onChange={(event) => change(field, event.target.value)} />}</Field>)}
          </Panel>
          <Actions end>
            <Button onClick={refresh} disabled={busy || !dirty}>Reload saved</Button>
            <Button variant="danger" onClick={() => setResetting(true)} disabled={!canWrite || busy}>Reset defaults</Button>
            <Button type="submit" variant="primary" disabled={!canWrite || busy || !dirty || Object.keys(previewErrors).length > 0}>Save branding</Button>
          </Actions>
        </form>
        <aside className="branding-preview-wrap" aria-label="Local sign-in preview">
          <div className="branding-preview-heading"><strong>Sign-in preview</strong><span>{Object.keys(previewErrors).length === 0 ? 'Valid local draft' : 'Fix invalid fields to save'}</span></div>
          <div className="branding-preview" ref={preview}>
            <div className="branding-preview-shell">
              <div className="branding-preview-brand">
                {previewLogo === null ? <span className="branding-preview-mark"><ImageIcon aria-hidden="true" /></span> : <span className="branding-preview-mark branding-preview-logo"><img src={previewLogo} alt="" /></span>}
                <strong>{draft.productName.trim() || session.workspace}</strong>
              </div>
              <div className="branding-preview-card">
                <h3>Sign in</h3><p>Continue to your account.</p>
                <label>Email address<input type="email" tabIndex={-1} readOnly value="alex@example.com" /></label>
                <label>Password<input type="password" tabIndex={-1} readOnly value="preview" /></label>
                <button type="button" tabIndex={-1}>Sign in</button>
                {safeLinks.length > 0 && <nav aria-label="Preview support links">{safeLinks.map(([label, url]) => <a key={label} href={url} target="_blank" rel="noreferrer">{label}</a>)}</nav>}
              </div>
            </div>
          </div>
          <p className="hint">This preview is rendered locally. It makes no request and does not restyle the console.</p>
        </aside>
      </div>
      {resetting && <ConfirmDialog title="Reset tenant branding?" body="The shipped palette, type, spacing and mark will replace the saved branding." confirmLabel="Reset branding" busy={busy} onConfirm={reset} onCancel={() => setResetting(false)} />}
    </Screen>
  );
}
