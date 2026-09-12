import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

/**
 * The class-name joiner every shadcn component is written against.
 *
 * `clsx` flattens the conditionals and `tailwind-merge` resolves the conflicts
 * in favour of the last one, which is what lets a caller pass `className` to a
 * component that already has an opinion about the same property.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}
