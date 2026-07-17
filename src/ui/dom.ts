/** Tiny DOM helpers — no framework, everything inspectable. */

type Attrs = Record<string, string | boolean | ((ev: Event) => void)>

export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: (Node | string | null)[]
): HTMLElementTagNameMap[K] {
  const el = document.createElement(tag)
  for (const [key, val] of Object.entries(attrs)) {
    if (typeof val === 'function') {
      el.addEventListener(key.replace(/^on/, ''), val)
    } else if (typeof val === 'boolean') {
      if (val) el.setAttribute(key, '')
    } else {
      el.setAttribute(key, val)
    }
  }
  for (const child of children) {
    if (child === null) continue
    el.append(child)
  }
  return el
}

/** Full-precision field element as inline code — shares are shown whole, never truncated. */
export function fe(value: bigint): HTMLElement {
  return h('code', { class: 'fe' }, value.toString())
}

/** A status chip: icon + text + color (never color alone — WCAG 1.4.1). */
export type ChipKind = 'ok' | 'alarm' | 'neutral' | 'warn'
export function chip(kind: ChipKind, icon: string, text: string): HTMLElement {
  return h('span', { class: `chip chip-${kind}` }, h('span', { 'aria-hidden': 'true' }, icon), ` ${text}`)
}

export function clear(el: HTMLElement): void {
  el.replaceChildren()
}
