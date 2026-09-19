import { useSyncExternalStore } from 'react';
import type { JSX } from 'react';
import { MoonIcon, SunIcon } from 'lucide-react';
import { setTheme, subscribe, themeNow } from '@/theme';
import { Screen, useTableDensity } from '@/ui';

export function Preferences(): JSX.Element {
  const theme = useSyncExternalStore(subscribe, themeNow, themeNow);
  const [density, setDensity] = useTableDensity();
  return (
    <Screen title="Preferences" description="Make this console comfortable to work in. Preferences are saved in this browser.">
      <div className="preference-settings">
        <section className="preference-row" aria-labelledby="appearance-title">
          <div><h3 id="appearance-title">Appearance</h3><p className="muted">Choose a light or dark workspace.</p></div>
          <div className="segmented-control" role="radiogroup" aria-label="Colour theme">
            <label><input type="radio" name="theme" value="light" checked={theme === 'light'} onChange={() => setTheme('light')} /><SunIcon aria-hidden="true" /><span>Light</span></label>
            <label><input type="radio" name="theme" value="dark" checked={theme === 'dark'} onChange={() => setTheme('dark')} /><MoonIcon aria-hidden="true" /><span>Dark</span></label>
          </div>
        </section>
        <section className="preference-row" aria-labelledby="density-title">
          <div><h3 id="density-title">Table density</h3><p className="muted">Adjust the space between rows in every table.</p></div>
          <div className="segmented-control" role="radiogroup" aria-label="Table density">
            <label><input type="radio" name="density" value="comfortable" checked={density === 'comfortable'} onChange={() => setDensity('comfortable')} /><span>Comfortable</span></label>
            <label><input type="radio" name="density" value="compact" checked={density === 'compact'} onChange={() => setDensity('compact')} /><span>Compact</span></label>
          </div>
        </section>
      </div>
    </Screen>
  );
}
