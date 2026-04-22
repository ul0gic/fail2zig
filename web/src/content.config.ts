import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';

const docs = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/docs' }),
  schema: z.object({
    title: z.string(),
    description: z.string().optional(),
    sidebar_position: z.number().optional(),
    category: z.string().optional(),
    audience: z.string().optional(),
    last_verified: z
      .union([z.string(), z.date()])
      .transform((val) => (val instanceof Date ? (val.toISOString().split('T')[0] ?? '') : val))
      .optional(),
  }),
});

export const collections = { docs };
