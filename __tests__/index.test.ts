/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: MIT
 */
import { describe, expect, it, vi } from 'vitest'

const main = vi.hoisted(() => ({
	run: vi.fn(),
}))
vi.mock('../src/main', () => main)

describe('index', () => {
	it('calls run when imported', async () => {
		await import('../src/index.js')

		expect(main.run).toHaveBeenCalled()
	})
})
