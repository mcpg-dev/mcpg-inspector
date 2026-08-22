# @mcpg/ui

Shared React component primitives and the design-token stylesheet behind every
MCPG web surface. Ships shadcn/ui-style components built on Radix, a `cn`
class-merging helper, and a single Tailwind v4 CSS-first stylesheet that owns the
palette, the dark variant, and the shared utilities. Requires **Node 20+** and
**pnpm 10+**.

The package is `private: true` — it is consumed inside this workspace over
`workspace:*` and is not published to npm.

## Quick start

Add the dependency and import the stylesheet first in the consuming app's own
global CSS, so the app's rules layer on top:

```jsonc
// package.json
{
  "dependencies": {
    "@mcpg/ui": "workspace:*"
  }
}
```

```css
/* src/app/globals.css */
@import '@mcpg/ui/globals.css';

/* App-specific @source directives, tokens, and rules go after the import. */
```

Wrap the app in the shared theme provider, and give `<html>` a
`suppressHydrationWarning` — `next-themes` sets the theme class synchronously
before React hydrates:

```tsx
import { ThemeProvider } from '@mcpg/ui/components/theme-provider';

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
```

Then import components. Both entry styles work; the per-component path is the
tree-shakeable one:

```tsx
import { Button } from '@mcpg/ui/components/button';
import { Card, CardContent } from '@mcpg/ui/components/card';
import { cn } from '@mcpg/ui/lib/utils';
```

## Entry points

| Export | Resolves to |
|---|---|
| `@mcpg/ui` | `src/index.ts` — barrel re-export of every component plus `cn` |
| `@mcpg/ui/globals.css` | `src/styles/globals.css` — the Tailwind entry point and design tokens |
| `@mcpg/ui/components/*` | `src/components/*.tsx` — one component per path |
| `@mcpg/ui/lib/utils` | `src/lib/utils.ts` — the `cn` helper |

`sideEffects` is declared as `**/*.css`, so a bundler may drop unused component
modules while keeping the stylesheet.

## Components

`accordion`, `badge`, `button`, `card`, `dialog`, `input`, `label`, `separator`,
`tabs`, `textarea`, `theme-provider`, `theme-toggle`.

`Accordion`, `Dialog`, and `Tabs` wrap Radix and are compound — each exports
its part components (`AccordionItem`, `DialogContent`, `TabsList` and so on)
alongside the root. `Label` and `Separator` wrap a single Radix element each.
`Card` is compound as well, but plain markup rather than a Radix wrapper.

`Button` and `Badge` express their variants with `class-variance-authority` and
export the variant function next to the component, so a consumer can reuse the
class recipe on a different element. `Button` offers the `default`,
`destructive`, `outline`, `secondary`, `ghost`, and `link` variants at the
`default`, `sm`, `lg`, `icon`, and `icon-sm` sizes, and accepts `asChild` to
render as a Radix `Slot` over a link or another element.

`ThemeProvider` wraps `next-themes` with the project defaults —
`attribute="class"` so `<html class="dark">` drives the `dark` variant,
`defaultTheme="system"` with `enableSystem` to honour the OS preference until a
user picks explicitly, and `disableTransitionOnChange` to avoid re-running every
animated property during a swap. `ThemeToggle` is the matching single-button
light/dark control; it renders a same-size placeholder until mount so the icon
never flashes and the layout never shifts.

`cn(...inputs)` composes `clsx` with `tailwind-merge`, so conditional classes
resolve and a later Tailwind utility beats an earlier conflicting one.

## Styling

`globals.css` is the whole Tailwind configuration. There is no
`tailwind.config` file and no JS preset — v4 processes the entire `@import`
chain as one unit, so a consuming app needs nothing but the import. The
stylesheet owns:

- the `@import "tailwindcss"` entry point, `tw-animate-css`, and the
  `@tailwindcss/typography` plugin (loaded via `@plugin`, which is what makes
  `prose` classes real rather than no-ops in MDX content);
- the class-based dark variant, `@variant dark (&:where(.dark, .dark *))`,
  written with `:where()` so utility classes keep winning on specificity;
- a `container` utility restoring the centered, padded box v4 dropped;
- the `@theme` token set — a monochrome `--color-*` palette with light values in
  `@theme` and dark overrides under `.dark`, a `--radius` scale, `--font-sans` /
  `--font-mono` stacks, and the `--animate-fade-in` / `--animate-blink` aliases;
- a base layer that applies the border colour globally and sets body background,
  foreground, font features, and selection colours;
- the shared utilities `.grid-bg`, `.text-balance`, `.scrollbar-thin`, and
  `.yaml-hl`, plus a highlight.js token theme for MDX code blocks.

Apps override any `--color-*`, `--font-*`, or radius token in their own CSS
after the import to take on a different visual identity.

One thing to get right when adding sources: Tailwind v4 resolves `@source` paths
**relative to the file that declares them**. This stylesheet declares its own
`src` tree and the sibling `@mcpg/web-shell` tree, because those sit outside a
consuming app's auto-scan root. An app declares its own extra sources — MDX
content directories, for instance — in its own CSS.

## Used by

`apps/landing`, `apps/link`, `apps/ai`, `apps/control-plane/ui`,
`apps/control-plane/server/static`, `apps/keycloak-theme`, and the
`@mcpg/web-shell` library.

## Develop

The package is source-only: consumers compile the TypeScript themselves, so
there is no build step. Type checking is the project's one target:

```bash
pnpm --filter ./libs/ui exec tsc -b --noEmit       # tsc --noEmit -p libs/ui/tsconfig.json
```

React and Tailwind are peer dependencies (`react` and `react-dom` `^18.3.0`,
`tailwindcss` `^4.2.0`) — the consuming app owns those versions.

## Licence

Apache-2.0.
