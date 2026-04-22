# fail2zig.com — web

Astro 5 + React 19 islands, statically built, deployed to **Cloudflare Workers
Static Assets** (not Pages — Pages is legacy). This directory covers both the
marketing site (Phase 9A) and the live attack-yourself demo (Phase 9B).

## Stack

- **Astro 5.x** — static output, `@astrojs/cloudflare` adapter
- **React 19.x** — islands only, most pages ship zero JS
- **TypeScript 5.x** — strict, no `any`, `noUncheckedIndexedAccess`
- **Tailwind 4.x** — CSS-first config via `@theme inline` in `src/styles/global.css`
- **OKLCH theme tokens** — ported verbatim from `.project/design/assets/theme.css`
- **pnpm 10+** — the only supported package manager (no npm/yarn)
- **Node v25 via nvm** — never apt/NodeSource; re-source nvm in every shell
- **Shiki** via `rehype-pretty-code` for syntax highlighting (docs/blog)
- **Self-hosted fonts** — `@fontsource/inter` + `@fontsource/jetbrains-mono`

## Commands

Always re-source nvm before running these in a non-interactive shell:

```bash
export NVM_DIR="$HOME/.nvm"
. "$NVM_DIR/nvm.sh"
nvm use 25 > /dev/null
```

Then, from `web/`:

```bash
pnpm install          # install deps
pnpm run dev          # astro dev — http://localhost:4321
pnpm run build        # build to dist/
pnpm run preview      # preview built output
pnpm run lint         # eslint flat config, --max-warnings 0
pnpm run typecheck    # astro check + tsc --noEmit
pnpm run format       # prettier --write
pnpm run format:check # prettier --check
```

## Approach: port the mockups, don't rewrite

`.project/design/` holds 5 polished HTML mockups (~3,890 lines) with the OKLCH
theme system and fully-designed chrome. They are the design, not throwaway
sketches. For each page:

1. Copy the mockup `<body>` content into the matching Astro page.
2. Replace repeated nav/footer with `<SiteNav />` + `<SiteFooter />`.
3. Keep the mockup's class names — Tailwind utilities compose additively.
4. Do tone/copy adjustments per-page in the Astro file, **not** during port.

See `.claude/agents/web-engineer.md` for the full workflow, prior-art tone
policy, and Phase 9B demo safety invariants.

## Deploy target

Cloudflare Workers Static Assets — see `wrangler.toml`. Route is
`fail2zig.com/*` on zone `fail2zig.com`. Lead owns the deploy; WEB does not
push to production.
