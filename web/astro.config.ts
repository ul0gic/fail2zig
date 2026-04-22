import { defineConfig } from 'astro/config';
import tailwindcss from '@tailwindcss/vite';
import sitemap from '@astrojs/sitemap';
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
  integrations: [
    sitemap({
      // Exclude placeholder pages that shouldn't be indexed yet.
      // /see-it-live is the Phase 9B coming-soon card — flip to
      // indexable when the demo ships.
      filter: (page) => !page.endsWith('/see-it-live/'),
      changefreq: 'weekly',
      priority: 0.7,
      // Bump the homepage priority so crawlers treat it as the
      // canonical entry rather than just another page. changefreq
      // already inherits 'weekly' from the top-level option.
      serialize: (item) => {
        if (item.url === 'https://fail2zig.com/') {
          item.priority = 1.0;
        }
        return item;
      },
    }),
  ],
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
