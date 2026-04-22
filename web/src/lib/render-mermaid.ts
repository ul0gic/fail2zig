// Shared mermaid rendering + click-to-enlarge modal.
// Consumers pick which blocks on the page are diagrams and this module
// lazy-imports mermaid only when there is at least one to render.

import type Mermaid from 'mermaid';

interface MermaidTarget {
  /** Element whose textContent holds the mermaid source. */
  source: Element;
  /** Element to replace with the rendered diagram container. */
  wrapper: Element;
}

let mermaidPromise: Promise<typeof Mermaid> | null = null;
let modalInstalled = false;

async function loadMermaid(): Promise<typeof Mermaid> {
  if (!mermaidPromise) {
    mermaidPromise = import('mermaid').then((m) => {
      const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
      m.default.initialize({
        startOnLoad: false,
        theme: isDark ? 'dark' : 'neutral',
        securityLevel: 'strict',
        fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, monospace',
        flowchart: { curve: 'basis', htmlLabels: true },
      });
      return m.default;
    });
  }
  return mermaidPromise;
}

export async function renderMermaidTargets(targets: MermaidTarget[]): Promise<void> {
  if (targets.length === 0) return;
  const mermaid = await loadMermaid();
  let n = 0;
  for (const t of targets) {
    const source = (t.source.textContent ?? '').trim();
    try {
      const { svg } = await mermaid.render(`mmd-${Date.now().toString()}-${(n++).toString()}`, source);
      const container = document.createElement('div');
      container.className = 'mermaid-rendered';
      container.setAttribute('role', 'button');
      container.setAttribute('tabindex', '0');
      container.setAttribute('aria-label', 'Click to enlarge diagram');
      container.innerHTML = svg;
      t.wrapper.replaceWith(container);
    } catch (err) {
      const errEl = document.createElement('pre');
      errEl.className = 'mermaid-error';
      errEl.textContent = 'mermaid render failed: ' + (err as Error).message;
      t.wrapper.replaceWith(errEl);
    }
  }
}

/**
 * Blocks rendered from markdown by rehype-pretty-code appear as
 * <figure><pre><code data-language="mermaid">...</code></pre></figure>.
 * We replace the outer figure so the copy-button wrapper goes away too.
 */
export function findDocBlocks(root: ParentNode = document): MermaidTarget[] {
  return Array.from(
    root.querySelectorAll<HTMLElement>('.doc-content code[data-language="mermaid"]'),
  ).map((code) => ({
    source: code,
    wrapper:
      code.closest('figure[data-rehype-pretty-code-figure]') ??
      code.closest('pre') ??
      code,
  }));
}

/**
 * Plain `<pre class="mermaid">{source}</pre>` blocks written by hand in
 * .astro pages (outside the docs content collection).
 */
export function findRawPreBlocks(root: ParentNode = document): MermaidTarget[] {
  return Array.from(root.querySelectorAll<HTMLElement>('pre.mermaid')).map((pre) => ({
    source: pre,
    wrapper: pre,
  }));
}

/**
 * Install a single document-level click-to-enlarge modal. Safe to call
 * more than once; subsequent calls are no-ops.
 */
export function installMermaidModal(): void {
  if (modalInstalled) return;
  modalInstalled = true;

  const existing = document.getElementById('mermaid-modal');
  const modal = existing ?? createModal();
  const content = modal.querySelector<HTMLElement>('.mermaid-modal-content');
  const closeBtn = modal.querySelector<HTMLButtonElement>('.mermaid-modal-close');
  if (!content || !closeBtn) return;

  const open = (svgSource: string) => {
    content.innerHTML = svgSource;
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
  };
  const close = () => {
    modal.classList.remove('open');
    content.innerHTML = '';
    document.body.style.overflow = '';
  };

  document.addEventListener('click', (e) => {
    const diagram = (e.target as HTMLElement).closest<HTMLElement>('.mermaid-rendered');
    if (diagram) {
      const svg = diagram.querySelector('svg');
      if (svg) open(svg.outerHTML);
      return;
    }
    if (e.target === modal) close();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && modal.classList.contains('open')) {
      close();
      return;
    }
    if (e.key === 'Enter' || e.key === ' ') {
      const active = document.activeElement as HTMLElement | null;
      if (active?.classList.contains('mermaid-rendered')) {
        e.preventDefault();
        const svg = active.querySelector('svg');
        if (svg) open(svg.outerHTML);
      }
    }
  });
  closeBtn.addEventListener('click', close);
}

function createModal(): HTMLElement {
  const modal = document.createElement('div');
  modal.className = 'mermaid-modal';
  modal.id = 'mermaid-modal';
  modal.setAttribute('role', 'dialog');
  modal.setAttribute('aria-modal', 'true');
  modal.setAttribute('aria-label', 'Enlarged diagram');
  modal.innerHTML =
    '<div class="mermaid-modal-inner">' +
    '<button type="button" class="mermaid-modal-close" aria-label="Close">close</button>' +
    '<div class="mermaid-modal-content"></div>' +
    '</div>';
  document.body.appendChild(modal);
  return modal;
}
