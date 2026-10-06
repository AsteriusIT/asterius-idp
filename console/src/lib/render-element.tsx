import { useRender } from '@base-ui/react/use-render';

/** Shared Base UI composition for passive semantic surfaces. */
export function RenderElement<Tag extends keyof React.JSX.IntrinsicElements>({
  tag, render, ...props
}: useRender.ComponentProps<Tag> & { tag: Tag }) {
  return useRender({ defaultTagName: tag, render, props });
}
