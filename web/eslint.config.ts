import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import security from 'eslint-plugin-security';
import astro from 'eslint-plugin-astro';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default tseslint.config(
  {
    ignores: ['dist/**', '.astro/**', 'node_modules/**', 'eslint.config.ts'],
  },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'error',
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
      '@typescript-eslint/consistent-type-imports': 'error',
      eqeqeq: 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      'no-console': 'warn',
    },
  },
  security.configs.recommended,
  ...astro.configs.recommended,
  // KNOWN UPSTREAM FALSE POSITIVE — scoped rule disables for `.astro`
  // templates only. `.ts`/`.tsx` source files keep the full
  // strict-type-checked rule set. The root causes are documented in
  // `.project/issues/open/ISSUE-007-web-lint-errors.md`.
  //
  // 1. `no-unsafe-return` on `.map((x) => <JSX/>)`.
  //    Astro declares `astroHTML.JSX.Element = HTMLElement | any`
  //    (see `node_modules/astro/astro-jsx.d.ts:38`). Union-with-any
  //    collapses to `any` in TypeScript, so every JSX-returning
  //    callback in a template trips the rule. Cannot be narrowed via
  //    declaration merging: `type` aliases don't merge, Astro's
  //    `astro-jsx.d.ts` is pulled in transitively via `astro/client`,
  //    so a local `jsx.d.ts` override never wins. The real upstream
  //    fix is Astro removing the `| any` arm. Tracked at:
  //    https://github.com/withastro/astro/issues (search "JSX.Element any").
  //
  // 2. `restrict-template-expressions` on content-collection entries.
  //    astro-eslint-parser resolves `astro:content` imports as `any`
  //    inside `.astro` files in some configurations even when the
  //    main `tsc --noEmit` typecheck is clean. The frontmatter TS
  //    pass still enforces strict typing for everything else.
  {
    files: ['**/*.astro'],
    rules: {
      '@typescript-eslint/no-unsafe-return': 'off',
      '@typescript-eslint/restrict-template-expressions': 'off',
    },
  },
  prettier
);
