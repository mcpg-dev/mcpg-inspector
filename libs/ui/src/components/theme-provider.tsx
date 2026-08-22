'use client';

import { ThemeProvider as NextThemesProvider } from 'next-themes';
import type { ComponentProps } from 'react';

/**
 * Shared theme provider for every web surface (landing, link, ai, cp-ui).
 *
 * Wraps `next-themes` with the project's defaults:
 *   - `attribute="class"` so `<html class="dark">` toggles the `.dark`
 *     variant defined in `@mcpg/ui/globals.css` (`@variant dark
 *     (&:where(.dark, .dark *))`).
 *   - `defaultTheme="system"` + `enableSystem` honour the user's OS
 *     preference until they explicitly pick light or dark.
 *   - `disableTransitionOnChange` skips one frame of CSS transitions
 *     during the swap, otherwise every animated property re-runs and
 *     the page flickers.
 *
 * `next-themes` also injects an inline `<script>` into `<head>` that
 * reads localStorage + system preference and sets the class
 * synchronously before first paint, so SSG-rendered pages don't FOUC.
 * For that to work, every consuming app's `<html>` must have
 * `suppressHydrationWarning` (the script mutates the class before
 * React hydrates).
 */
export function ThemeProvider({
  children,
  ...props
}: ComponentProps<typeof NextThemesProvider>) {
  return (
    <NextThemesProvider
      attribute="class"
      defaultTheme="system"
      enableSystem
      disableTransitionOnChange
      {...props}
    >
      {children}
    </NextThemesProvider>
  );
}
