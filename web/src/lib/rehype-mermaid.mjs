import { visit } from 'unist-util-visit';

/**
 * Transforms fenced `mermaid` code blocks into `<pre class="mermaid">…</pre>`
 * before rehype-pretty-code runs, so those blocks are left untouched and
 * mermaid's client-side auto-render picks them up on page load.
 */
export default function rehypeMermaid() {
  return (tree) => {
    visit(tree, 'element', (node, index, parent) => {
      if (!parent || typeof index !== 'number') return;
      if (node.tagName !== 'pre') return;
      const code = node.children.find((c) => c.type === 'element' && c.tagName === 'code');
      if (!code) return;
      const classes = Array.isArray(code.properties?.className) ? code.properties.className : [];
      const isMermaid = classes.some(
        (c) => typeof c === 'string' && c === 'language-mermaid'
      );
      if (!isMermaid) return;
      const raw = (code.children || [])
        .filter((c) => c.type === 'text')
        .map((c) => c.value)
        .join('');
      parent.children[index] = {
        type: 'element',
        tagName: 'pre',
        properties: { className: ['mermaid'] },
        children: [{ type: 'text', value: raw }],
      };
    });
  };
}
