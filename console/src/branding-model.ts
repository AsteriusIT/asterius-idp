/** The validated theme document shared by the admin API and runtime pages. */
export interface ThemeDocument {
  readonly palette: {
    readonly background: string;
    readonly text: string;
    readonly muted_text: string;
    readonly accent: string;
    readonly accent_text: string;
    readonly danger: string;
  };
  readonly font: string;
  readonly radius_px: number;
  readonly spacing_px: number;
  readonly product_name?: string;
  readonly support?: {
    readonly help_url?: string;
    readonly privacy_url?: string;
    readonly terms_url?: string;
  };
  readonly icon?: string;
  readonly logo?: AssetReference;
  readonly favicon?: AssetReference;
}

export interface AssetReference {
  readonly digest: string;
  readonly content_type: string;
}

/** The useful constraints in the schema returned alongside the theme. */
export interface ThemeSchema {
  readonly properties?: Readonly<Record<string, {
    readonly maxLength?: number;
    readonly enum?: readonly (string | null)[];
    readonly properties?: Readonly<Record<string, { readonly maxLength?: number }>>;
  }>>;
}

export interface ThemeEnvelope {
  readonly theme: ThemeDocument;
  readonly schema: ThemeSchema;
}

/** Strings are retained while editing so incomplete input is not normalised away. */
export interface BrandingDraft {
  readonly palette: ThemeDocument['palette'];
  readonly font: string;
  readonly radius: string;
  readonly spacing: string;
  readonly productName: string;
  readonly helpUrl: string;
  readonly privacyUrl: string;
  readonly termsUrl: string;
  readonly icon?: string;
  readonly logo?: AssetReference;
  readonly favicon?: AssetReference;
}

export type BrandingField =
  | keyof ThemeDocument['palette']
  | 'font'
  | 'radius'
  | 'spacing'
  | 'productName'
  | 'helpUrl'
  | 'privacyUrl'
  | 'termsUrl'
  | 'logo';

export type BrandingErrors = Partial<Record<BrandingField, string>>;

export function draftOf(theme: ThemeDocument): BrandingDraft {
  return {
    palette: { ...theme.palette },
    font: theme.font,
    radius: String(theme.radius_px),
    spacing: String(theme.spacing_px),
    productName: theme.product_name ?? '',
    helpUrl: theme.support?.help_url ?? '',
    privacyUrl: theme.support?.privacy_url ?? '',
    termsUrl: theme.support?.terms_url ?? '',
    ...(theme.icon === undefined ? {} : { icon: theme.icon }),
    ...(theme.logo === undefined ? {} : { logo: theme.logo }),
    ...(theme.favicon === undefined ? {} : { favicon: theme.favicon }),
  };
}

export function documentOf(draft: BrandingDraft): ThemeDocument {
  const support = Object.fromEntries(
    [
      ['help_url', draft.helpUrl.trim()],
      ['privacy_url', draft.privacyUrl.trim()],
      ['terms_url', draft.termsUrl.trim()],
    ].filter(([, value]) => value !== ''),
  );
  return {
    palette: { ...draft.palette },
    font: draft.font,
    radius_px: Number(draft.radius),
    spacing_px: Number(draft.spacing),
    ...(draft.productName.trim() === '' ? {} : { product_name: draft.productName.trim() }),
    ...(Object.keys(support).length === 0 ? {} : { support }),
    ...(draft.icon === undefined ? {} : { icon: draft.icon }),
    ...(draft.logo === undefined ? {} : { logo: draft.logo }),
    ...(draft.favicon === undefined ? {} : { favicon: draft.favicon }),
  };
}

export function isDirty(saved: ThemeDocument, draft: BrandingDraft): boolean {
  // The API serialises object members in its own stable order. Compare two
  // documents assembled here so JSON member order never invents a change.
  return JSON.stringify(documentOf(draft)) !== JSON.stringify(documentOf(draftOf(saved)));
}

function channel(hex: string, offset: number): number {
  return Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
}

function luminance(hex: string): number {
  const linear = (value: number): number =>
    value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  return 0.2126 * linear(channel(hex, 1)) + 0.7152 * linear(channel(hex, 3)) + 0.0722 * linear(channel(hex, 5));
}

export function contrastRatio(one: string, other: string): number {
  const first = luminance(one);
  const second = luminance(other);
  const lighter = Math.max(first, second);
  const darker = Math.min(first, second);
  return (lighter + 0.05) / (darker + 0.05);
}

function validHttpsUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === 'https:' && url.host !== '' && url.username === '' && url.password === '' && url.hash === '';
  } catch {
    return false;
  }
}

/** Client-side field guidance; the server remains the authoritative validator. */
export function validateDraft(draft: BrandingDraft, schema: ThemeSchema): BrandingErrors {
  const errors: BrandingErrors = {};
  const colour = /^#[0-9a-fA-F]{6}$/;
  for (const [name, value] of Object.entries(draft.palette) as [keyof ThemeDocument['palette'], string][]) {
    if (!colour.test(value)) errors[name] = 'Use a six-digit colour such as #4054e8.';
  }
  for (const [foreground, background] of [
    ['text', 'background'],
    ['muted_text', 'background'],
    ['accent_text', 'accent'],
    ['danger', 'background'],
  ] as const) {
    if (colour.test(draft.palette[foreground]) && colour.test(draft.palette[background]) &&
        contrastRatio(draft.palette[foreground], draft.palette[background]) < 4.5) {
      errors[foreground] = 'This pair needs at least 4.5:1 contrast.';
    }
  }
  const fonts = schema.properties?.font?.enum?.filter((value): value is string => typeof value === 'string');
  if (fonts !== undefined && !fonts.includes(draft.font)) errors.font = 'Choose a font hosted by this server.';
  const radius = Number(draft.radius);
  if (!Number.isInteger(radius) || radius < 0 || radius > 24) errors.radius = 'Use a whole number from 0 to 24.';
  const spacing = Number(draft.spacing);
  if (!Number.isInteger(spacing) || spacing < 4 || spacing > 16) errors.spacing = 'Use a whole number from 4 to 16.';
  const nameLimit = schema.properties?.product_name?.maxLength ?? 64;
  const name = draft.productName.trim();
  if (name.length > nameLimit || [...name].some((character) => /[\u0000-\u001f\u007f]/.test(character))) {
    errors.productName = `Use printable text no longer than ${nameLimit} characters.`;
  }
  const linkLimit = schema.properties?.support?.properties?.help_url?.maxLength ?? 256;
  for (const [field, value] of [
    ['helpUrl', draft.helpUrl],
    ['privacyUrl', draft.privacyUrl],
    ['termsUrl', draft.termsUrl],
  ] as const) {
    const trimmed = value.trim();
    if (trimmed !== '' && (trimmed.length > linkLimit || !validHttpsUrl(trimmed))) {
      errors[field] = 'Use an absolute HTTPS URL without credentials or a fragment.';
    }
  }
  return errors;
}

/** Maps the server's JSON pointer back to the corresponding form control. */
export function refusalField(message: string): BrandingField | null {
  const paths: readonly (readonly [string, BrandingField])[] = [
    ['/palette/background', 'background'], ['/palette/text', 'text'],
    ['/palette/muted_text', 'muted_text'], ['/palette/accent', 'accent'],
    ['/palette/accent_text', 'accent_text'], ['/palette/danger', 'danger'],
    ['/product_name', 'productName'], ['/support/help_url', 'helpUrl'],
    ['/support/privacy_url', 'privacyUrl'], ['/support/terms_url', 'termsUrl'],
    ['/radius_px', 'radius'], ['/spacing_px', 'spacing'], ['/font', 'font'], ['/logo', 'logo'],
  ];
  return paths.find(([path]) => message.includes(`\`${path}\``))?.[1] ?? null;
}

export function validateLogo(file: File): string | null {
  if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) return 'Choose a PNG, JPEG or WebP image.';
  if (file.size > 200 * 1024) return 'The logo must be no larger than 200 KiB.';
  return null;
}
