import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import rehypePrettyCode from 'rehype-pretty-code';
import rehypeSlug from 'rehype-slug';
import rehypeAutolinkHeadings from 'rehype-autolink-headings';

// Pure static build — Astro's default output drops straight into
// Cloudflare Pages without any adapter. No SSR, no image-service
// compile step, no wrangler dependency.
//
// https://astro.build/config
export default defineConfig({
  site: 'https://fail2zig.com',
  output: 'static',
  server: { host: true },
  markdown: {
    syntaxHighlight: false,
    rehypePlugins: [
      rehypeSlug,
      [
        rehypeAutolinkHeadings,
        {
          behavior: 'append',
          properties: { className: ['heading-anchor'], ariaLabel: 'Link to section' },
        },
      ],
      [
        rehypePrettyCode,
        {
          theme: 'github-dark-default',
          keepBackground: false,
        },
      ],
    ],
  },
  vite: {
    plugins: [tailwindcss()],
  },
});
