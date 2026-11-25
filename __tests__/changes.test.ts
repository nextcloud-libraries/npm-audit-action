/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: MIT
 */

import type { Change } from '../src/changes.ts'

import { execFileSync } from 'node:child_process'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { formatChanges, getChanges } from '../src/changes.ts'

describe('formatChanges', () => {
	it('returns nothing without changes', () => {
		expect(formatChanges([])).toBe('')
	})

	it('wraps the changes in a collapsible section', () => {
		const output = formatChanges([{ type: 'add', key: 'node_modules/foo', name: 'foo', version: '1.0.0' }])
		expect(output).toMatch(/^\n\n## Updated dependencies\n<details>\n<summary>Show all 1 changed packages<\/summary>\n\n### Added dependencies\n/)
		expect(output).toMatch(/\n<\/details>\n$/)
		expect(output).not.toMatch(/\[\{/)
	})

	it('lists every kind of change on its own line', () => {
		const changes: Change[] = [
			{ type: 'add', key: 'node_modules/added', name: 'added', version: '1.0.0' },
			{ type: 'remove', key: 'node_modules/removed', name: 'removed', version: '2.0.0' },
			{ type: 'version', key: 'node_modules/bumped', name: 'bumped', fromVersion: '1.0.0', toVersion: '1.0.1' },
			{ type: 'version', key: 'node_modules/other', name: 'other', fromVersion: '3.0.0', toVersion: '3.1.0' },
			{ type: 'key', name: 'moved', version: '4.0.0', fromKey: 'node_modules/a/node_modules/moved', toKey: 'node_modules/moved' },
		]

		const lines = formatChanges(changes).split('\n')
		expect(lines).toContain('### Added dependencies')
		expect(lines).toContain('* `added` @ 1.0.0')
		expect(lines).toContain('### Removed dependencies')
		expect(lines).toContain('* `removed` @ 2.0.0')
		expect(lines).toContain('### Updated dependencies')
		expect(lines).toContain('* `bumped` from 1.0.0 to 1.0.1')
		expect(lines).toContain('* `other` from 3.0.0 to 3.1.0')
		expect(lines).toContain('* `moved` @ 4.0.0 from node_modules/a/node_modules/moved to node_modules/moved')
	})
})

describe('getChanges', () => {
	let cwd: string

	/**
	 * Write a lockfile v3 with the given packages
	 *
	 * @param packages - Map of package name to version
	 */
	async function writeLockFile(packages: Record<string, string>) {
		const lock = {
			name: 'test',
			lockfileVersion: 3,
			packages: {
				'': { name: 'test' },
				...Object.fromEntries(Object.entries(packages).map(([name, version]) => [`node_modules/${name}`, { version }])),
			},
		}
		await writeFile(join(cwd, 'package-lock.json'), JSON.stringify(lock))
	}

	beforeEach(async () => {
		cwd = await mkdtemp(join(tmpdir(), 'npm-audit-action-'))
	})

	afterEach(async () => {
		vi.unstubAllEnvs()
		await rm(cwd, { recursive: true, force: true })
	})

	it('lists the changes between HEAD and the working tree', async () => {
		await writeLockFile({ kept: '1.0.0', bumped: '1.0.0', removed: '1.0.0' })
		execFileSync('git', ['init', '-q'], { cwd })
		execFileSync('git', ['add', '.'], { cwd })
		execFileSync('git', ['-c', 'user.name=test', '-c', 'user.email=test@example.com', 'commit', '-q', '-m', 'init'], { cwd })
		await writeLockFile({ kept: '1.0.0', bumped: '1.1.0', added: '2.0.0' })

		const changes = await getChanges(cwd)
		expect(changes).toHaveLength(3)
		expect(changes).toContainEqual({ type: 'version', key: 'node_modules/bumped', name: 'bumped', fromVersion: '1.0.0', toVersion: '1.1.0' })
		expect(changes).toContainEqual({ type: 'add', key: 'node_modules/added', name: 'added', version: '2.0.0' })
		expect(changes).toContainEqual({ type: 'remove', key: 'node_modules/removed', name: 'removed', version: '1.0.0' })
	})

	it('throws outside of a git repository', async () => {
		vi.stubEnv('GIT_CEILING_DIRECTORIES', dirname(cwd))
		await writeLockFile({ foo: '1.0.0' })
		await expect(getChanges(cwd)).rejects.toThrow(/git ls-tree/)
	})
})
