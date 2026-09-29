import { useEffect, useState } from 'react';
import { useUnsavedChanges } from './navigation-guard';
import { Button } from './ui';

/** A discard choice stays inside the editor dialog, never opening a second modal. */
export function useDialogDraft(dirty: boolean, busy: boolean, close: () => void) {
  useUnsavedChanges(dirty);
  const [confirming, setConfirming] = useState(false);
  useEffect(() => { if (!dirty) setConfirming(false); }, [dirty]);
  const requestClose = () => {
    if (busy) return;
    if (dirty) setConfirming(true); else close();
  };
  const confirmation = confirming ? <div className="message warning" role="alert">
    <p>Your changes have not been saved.</p>
    <div className="actions"><Button autoFocus onClick={() => setConfirming(false)}>Keep editing</Button>
      <Button variant="danger" onClick={() => { setConfirming(false); close(); }}>Discard changes</Button></div>
  </div> : null;
  return { requestClose, confirmation };
}
