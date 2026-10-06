import { ToggleGroup, ToggleGroupItem } from './components/ui/toggle-group';
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
          <ToggleGroup className="preference-choice" value={[theme]} aria-label="Colour theme" onValueChange={values => { const choice = values[0]; if (choice === 'light' || choice === 'dark') setTheme(choice); }}>
            <ToggleGroupItem value="light"><SunIcon data-icon="inline-start" aria-hidden="true" />Light</ToggleGroupItem>
            <ToggleGroupItem value="dark"><MoonIcon data-icon="inline-start" aria-hidden="true" />Dark</ToggleGroupItem>
          </ToggleGroup>
        </section>
        <section className="preference-row" aria-labelledby="density-title">
          <div><h3 id="density-title">Table density</h3><p className="muted">Adjust the space between rows in every table.</p></div>
          <ToggleGroup className="preference-choice" value={[density]} aria-label="Table density" onValueChange={values => { const choice = values[0]; if (choice === 'comfortable' || choice === 'compact') setDensity(choice); }}>
            <ToggleGroupItem value="comfortable">Comfortable</ToggleGroupItem>
            <ToggleGroupItem value="compact">Compact</ToggleGroupItem>
          </ToggleGroup>
        </section>
      </div>
    </Screen>
  );
}
