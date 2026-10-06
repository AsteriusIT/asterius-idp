import { Badge } from '../ui';
import type { Review } from '../access-reviews-model';

export function ReviewState({ review }: Readonly<{ review: Review }>) {
  const state = review.cancelled_at ? 'Cancelled' : review.completed_at ? 'Completed' : 'Open';
  return <Badge tone={state === 'Completed' ? 'ok' : state === 'Cancelled' ? 'warn' : 'neutral'}>{state}</Badge>;
}
