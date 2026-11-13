/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: MIT
 */
import { beforeEach, describe, expect, it, vi } from 'vitest'
import { formatNpmAuditOutput, runNpmAudit } from '../src/main.js'

const core = vi.hoisted(() => ({
	debug: vi.fn(),
	info: vi.fn(),
}))
const childProcess = vi.hoisted(() => ({
	exec: vi.fn(),
}))
vi.mock('node:child_process', () => childProcess)
vi.mock('@actions/core', () => core)

describe('runNpmAudit', () => {
	beforeEach(() => {
		vi.resetAllMocks()
	})

	it('calls exec with correct command', async () => {
		childProcess.exec.mockImplementationOnce((command, callback) => {
			callback(null, '{}', '')
		})

		const output = await runNpmAudit(false)
		expect(output).toBe('{}')
		expect(childProcess.exec).toHaveBeenCalled()
		expect(childProcess.exec.mock.calls[0][0]).toMatch('npm audit --json')
	})

	it('calls exec with correct fix-command', async () => {
		childProcess.exec.mockImplementationOnce((command, callback) => {
			callback(null, '{}', '')
		})

		const output = await runNpmAudit(true)
		expect(output).toBe('{}')
		expect(childProcess.exec).toHaveBeenCalled()
		expect(childProcess.exec.mock.calls[0][0]).toMatch('npm audit --json fix')
	})

	it('Outputs only the JSON', async () => {
		// when fixing it also outputs the install stuff
		childProcess.exec.mockImplementationOnce((command, callback) => {
			callback(
				null,
				'add   foo  6.5.4 -> 6.5.5   \nadd   bar  0.1.0 -> 1.0.0   \n{\n}',
				'',
			)
		})

		const output = await runNpmAudit(false)
		expect(output).toBe('{\n}')
	})

	it('writes debug output', async () => {
		childProcess.exec.mockImplementationOnce((command, callback) => {
			callback(null, '{}', 'Some note')
		})

		await runNpmAudit(false)
		expect(childProcess.exec).toHaveBeenCalled()
		expect(core.debug).toHaveBeenCalledWith('[npm audit]: Some note')
	})

	it('rejects on error', async () => {
		childProcess.exec.mockImplementationOnce((command, callback) => {
			callback(new Error('Some error'), '', 'An error happened')
		})

		expect(async () => await runNpmAudit(false)).rejects.toThrowError(/Some error/)
		expect(childProcess.exec).toHaveBeenCalled()
		expect(core.debug).toHaveBeenCalledWith('[npm audit]: An error happened')
	})
})

describe('formatNpmAuditOutput', () => {
	it('formats empty output correctly', async () => {
		const data = {
			vulnerabilities: {},
		}

		/// @ts-expect-error mocking the object
		const output = await formatNpmAuditOutput(data)
		expect(core.info).toHaveBeenCalledWith('Found 0 fixable issues')
		expect(output).toMatch(/# Audit report/)
		expect(output).toMatch(/No fixable problems found \(0 unfixable\)/)
	})

	it('formats output correctly for only unfixables', async () => {
		const data = {
			vulnerabilities: {
				foo: {
					fixAvailable: false,
				},
			},
		}

		/// @ts-expect-error mocking the object
		const output = await formatNpmAuditOutput(data)
		expect(core.info).toHaveBeenCalledWith('Found 0 fixable issues')
		expect(output).toMatch(/# Audit report/)
		expect(output).toMatch(/No fixable problems found \(1 unfixable\)/)
	})

	it('formats output correctly for force fixable', async () => {
		const data = {
			vulnerabilities: {
				foo: {
					fixAvailable: {
						name: 'foo',
						version: '42.0.0',
						isSemVerMajor: true,
					},
				},
			},
		}

		/// @ts-expect-error mocking the object
		const output = await formatNpmAuditOutput(data)
		expect(core.info).toHaveBeenCalledWith('Found 0 fixable issues')
		expect(output).toMatch(/# Audit report/)
		expect(output).toMatch(/No fixable problems found \(0 unfixable, 1 only fixable manually using --force\)/)
	})

	it('treats a transitive package with its own advisory as fixable', async () => {
		const advisory = { title: 'Some advisory', severity: 'high', url: 'https://example.com/advisory', source: 1, name: 'foo', dependency: 'foo' }
		const data = {
			vulnerabilities: {
				foo: { name: 'foo', isDirect: false, fixAvailable: true, via: [advisory], range: '<1.2.3', nodes: ['node_modules/bar/node_modules/foo'] },
			},
		}

		/// @ts-expect-error mocking the object
		const output = await formatNpmAuditOutput(data)
		expect(core.info).toHaveBeenCalledWith('Found 1 fixable issues')
		expect(output).toMatch(/This audit fix resolves 1 of the total 1 vulnerabilities/)
		expect(output).toMatch(/### `foo`/)
	})

	it('does not treat a package as fixable if its parent needs --force', async () => {
		const advisory = { title: 'Some advisory', severity: 'high', url: 'https://example.com/advisory', source: 1, name: 'parent', dependency: 'parent' }
		const data = {
			vulnerabilities: {
				parent: { name: 'parent', isDirect: false, fixAvailable: { name: 'x', version: '2.0.0', isSemVerMajor: true }, via: [advisory], range: '*', nodes: ['node_modules/parent'] },
				child: { name: 'child', isDirect: false, fixAvailable: true, via: ['parent'], range: '*', nodes: ['node_modules/child'] },
			},
		}

		/// @ts-expect-error mocking the object
		const output = await formatNpmAuditOutput(data)
		expect(core.info).toHaveBeenCalledWith('Found 0 fixable issues')
		expect(output).toMatch(/No fixable problems found \(0 unfixable, 2 only fixable manually using --force\)/)
	})

	it('only counts packages without any fix as unfixable', async () => {
		const data = {
			vulnerabilities: {
				a: { name: 'a', isDirect: true, fixAvailable: false, via: [], range: '*', nodes: [] },
				b: { name: 'b', isDirect: true, fixAvailable: { name: 'b', version: '2.0.0', isSemVerMajor: true }, via: [], range: '*', nodes: [] },
				c: { name: 'c', isDirect: true, fixAvailable: false, via: [], range: '*', nodes: [] },
			},
		}

		/// @ts-expect-error mocking the object
		const output = await formatNpmAuditOutput(data)
		expect(output).toMatch(/No fixable problems found \(2 unfixable, 1 only fixable manually using --force\)/)
	})
})
