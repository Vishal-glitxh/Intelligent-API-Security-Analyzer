import { describe, expect, it } from 'vitest'
import viteConfig from '../../vite.config'

describe('Vite development server configuration', () => {
  it('binds to loopback and retains the local API and health proxies', () => {
    expect(viteConfig.server?.host).toBe('127.0.0.1')
    expect(viteConfig.server?.proxy).toMatchObject({
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/health': { target: 'http://localhost:8000', changeOrigin: true },
    })
  })
})
