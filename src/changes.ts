/**
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 */

import ChangesTree from 'diff-package-lock/dist/Tree.js'

interface PackageChange {
	type: 'add' | 'remove'
	key: string
	name: string
	version: string
}

interface PackageVersionChange {
	type: 'version'
	name: string
	key: string
	fromVersion: string
	toVersion: string
}

interface PackageDependencyChange {
	type: 'key'
	name: string
	version: string
	fromKey: string
	toKey: string
}

type Change = PackageChange | PackageVersionChange | PackageDependencyChange

/**
 * Get the Markdown formatted list of changes between current HEAD and the changes on disk.
 *
 * @param cwd - The current working directory to check for changes
 */
export async function getChanges(cwd: string = process.cwd()): Promise<Change[]> {
	const fromTree = new ChangesTree.default('HEAD', { cwd })
	const toTree = new ChangesTree.default('disk', { cwd })
	const changes: { toJSON(): Change }[] = await fromTree.getChanges(toTree)
	return changes.map((change) => change.toJSON())
}

/**
 * Format the list of changes as Markdown
 *
 * @param changes - The list of changes to format
 */
export function formatChanges(changes: Change[]): string {
	let result = ''
	const added = changes.filter(({ type }) => type === 'add') as PackageChange[]
	if (added.length) {
		result += '### Added dependencies\n'
		result += added.map((change) => `* \`${change.name}\` @ ${change.version}`).join('\n')
		result += '\n\n'
	}

	const removed = changes.filter(({ type }) => type === 'remove') as PackageChange[]
	if (removed.length) {
		result += '### Removed dependencies\n'
		result += removed.map((change) => `* \`${change.name}\` @ ${change.version}`).join('\n')
		result += '\n\n'
	}

	const updated = changes.filter(({ type }) => type === 'version') as PackageVersionChange[]
	const keyUpdated = changes.filter(({ type }) => type === 'key') as PackageDependencyChange[]
	if (updated.length || keyUpdated.length) {
		result += '### Updated dependencies\n'
		result += updated.map((change) => `* \`${change.name}\` from ${change.fromVersion} to ${change.toVersion}`).join('\n')
		result += keyUpdated.map((change) => `* \`${change.name}\` @ ${change.version} from ${change.fromKey} to ${change.toKey}`).join('\n')
		result += '\n\n'
	}

	return result
}
