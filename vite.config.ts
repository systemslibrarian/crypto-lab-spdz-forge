/// <reference types="vitest/config" />
import { defineConfig } from 'vite'

export default defineConfig({
  base: '/crypto-lab-spdz-forge/',
  test: {
    include: ['src/**/*.test.ts'],
    environment: 'node',
  },
})
