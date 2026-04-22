import { defineConfig } from 'astro/config';
import cloudflare from '@astrojs/cloudflare';
import react from '@astrojs/react';
import mdx from '@astrojs/mdx';
import tailwindcss from '@tailwindcss/vite';
import rehypePrettyCode from 'rehype-pretty-code';
import rehypeSlug from 'rehype-slug';
import rehypeAutolinkHeadings from 'rehype-autolink-headings';

// https://astro.build/config
export default defineConfig({
  site: 'https://fail2zig.com',
  output: 'static',
  server: { host: true },
  adapter: cloudflare({
    imageService: 'compile',
  }),
  integrations: [react(), mdx()],
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
