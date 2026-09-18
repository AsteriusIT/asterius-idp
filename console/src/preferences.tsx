import { useSyncExternalStore } from 'react';
import type { JSX } from 'react';
import { CheckIcon, MoonIcon, Rows3Icon, Rows4Icon, SunIcon } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';
import { setTheme, subscribe, themeNow } from '@/theme';
import { Panel, Screen, useTableDensity } from '@/ui';

export function Preferences(): JSX.Element {
  const theme = useSyncExternalStore(subscribe, themeNow, themeNow);
  const [density, setDensity] = useTableDensity();

  return (
    <Screen
      title="Settings"
      description="Display preferences for this browser. Tenant configuration stays on its own page."
    >
      <div className="settings-grid">
        <Panel
          title="Appearance"
          description="Choose the palette used throughout the console."
        >
          <div className="preference-options" role="group" aria-label="Colour theme">
            <PreferenceOption
              active={theme === 'light'}
              icon={SunIcon}
              title="Light"
              description="Bright surfaces and dark text."
              onSelect={() => setTheme('light')}
            />
            <PreferenceOption
              active={theme === 'dark'}
              icon={MoonIcon}
              title="Dark"
              description="Dim surfaces for low-light work."
              onSelect={() => setTheme('dark')}
            />
          </div>
        </Panel>

        <Panel
          title="Data density"
          description="Set row spacing once for every table in the application."
        >
          <div className="preference-options" role="group" aria-label="Table density">
            <PreferenceOption
              active={density === 'comfortable'}
              icon={Rows4Icon}
              title="Comfortable"
              description="More room for scanning and touch."
              onSelect={() => setDensity('comfortable')}
            />
            <PreferenceOption
              active={density === 'compact'}
              icon={Rows3Icon}
              title="Compact"
              description="More rows in operational views."
              onSelect={() => setDensity('compact')}
            />
          </div>
        </Panel>
      </div>
    </Screen>
  );
}

function PreferenceOption({
  active,
  icon: Icon,
  title,
  description,
  onSelect,
}: {
  active: boolean;
  icon: LucideIcon;
  title: string;
  description: string;
  onSelect: () => void;
}): JSX.Element {
  return (
    <Button
      variant="outline"
      className={cn('preference-option', active && 'is-selected')}
      aria-pressed={active}
      onClick={onSelect}
    >
      <span className="preference-icon"><Icon aria-hidden="true" /></span>
      <span>
        <strong>{title}</strong>
        <small>{description}</small>
      </span>
      {active && <CheckIcon className="preference-check" aria-hidden="true" />}
    </Button>
  );
}
