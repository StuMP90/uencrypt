import { useEffect, useRef } from 'react'
import { EventsOn } from '../wailsjs/runtime/runtime'
import { main } from '../wailsjs/go/models'

export type FileInfo = main.FileInfo
export type OpResult = main.OpResult
export type KeyInfo = main.KeyInfo
export type KeyringState = main.KeyringState

export interface Prompt {
  id: string
  kind: 'passphrase' | 'confirm'
  title: string
  message: string
  error: string
  confirm: string
}

export interface Progress {
  file: string
  done: number
  total: number
}

// Wails rejects bound-method promises with the Go error string.
export function errText(e: unknown): string {
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return String(e)
}

// useEvent subscribes to a backend event for the component's lifetime,
// always calling the latest handler.
export function useEvent<T>(name: string, handler: (data: T) => void) {
  const ref = useRef(handler)
  ref.current = handler
  useEffect(() => EventsOn(name, (data: T) => ref.current(data)), [name])
}

export function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v < 10 ? v.toFixed(1) : Math.round(v)} ${units[i]}`
}

export function baseName(p: string): string {
  return p.split(/[\\/]/).pop() || p
}

// strength gives a rough 0-4 score for a typed passphrase.
export function strength(p: string): { score: number; label: string } {
  if (!p) return { score: 0, label: '' }
  let pool = 0
  if (/[a-z]/.test(p)) pool += 26
  if (/[A-Z]/.test(p)) pool += 26
  if (/[0-9]/.test(p)) pool += 10
  if (/[^a-zA-Z0-9]/.test(p)) pool += 33
  const bits = p.length * Math.log2(Math.max(pool, 2))
  if (bits < 40) return { score: 1, label: 'Weak' }
  if (bits < 64) return { score: 2, label: 'Fair' }
  if (bits < 90) return { score: 3, label: 'Good' }
  return { score: 4, label: 'Strong' }
}
