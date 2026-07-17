import './style.css'
import { renderAdditionPanel } from './ui/panels/addition'
import { renderBeaverPanel } from './ui/panels/beaver'
import { renderMacPanel } from './ui/panels/maccheck'
import { renderPreprocessingPanel } from './ui/panels/preprocessing'
import { renderVariancePanel } from './ui/panels/variance'

function mount(id: string, render: (el: HTMLElement) => void): void {
  const el = document.getElementById(id)
  if (!el) throw new Error(`missing mount point #${id}`)
  render(el)
}

mount('panel-add', renderAdditionPanel)
mount('panel-beaver', renderBeaverPanel)
mount('panel-mac', renderMacPanel)
mount('panel-pre', renderPreprocessingPanel)
mount('panel-var', renderVariancePanel)
