/**
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 */

import type { Change, PackageChange, PackageKeyChange, PackageVersionChange } from 'diff-package-lock/dist/Tree.js'

import TreeModule from 'diff-package-lock/dist/Tree.js'

export type { Change }

const Tree = 'default' in TreeModule ? TreeModule.default : TreeModule

/**
 * Get the list of changes between the lock file in the current HEAD and the lock file on disk.
 *
 * @param cwd - The directory containing the lock file
 */
export async function getChanges(cwd: string = process.cwd()): Promise<Change[]> {
	const fromTree = new Tree('HEAD', { cwd })
	const toTree = new Tree('disk', { cwd })
	const changes = await fromTree.getChanges(toTree)
	return changes.map((change) => change.toJSON())
}

/**
 * Format the list of changes as a collapsible Markdown section.
 * Returns an empty string if there are no changes.
 *
 * @param changes - The list of changes to format
 */
export function formatChanges(changes: Change[]): string {
	if (changes.length === 0) {
		return ''
	}

	let result = `\n\n## Updated dependencies\n<details>\n<summary>Show all ${changes.length} changed packages</summary>\n\n`

	const added = changes.filter(({ type }) => type === 'add') as PackageChange[]
	if (added.length) {
		result += '### Added dependencies\n'
		result += added.map((change) => `* \`${change.name}\` @ ${change.version}\n`).join('')
		result += '\n'
	}

	const removed = changes.filter(({ type }) => type === 'remove') as PackageChange[]
	if (removed.length) {
		result += '### Removed dependencies\n'
		result += removed.map((change) => `* \`${change.name}\` @ ${change.version}\n`).join('')
		result += '\n'
	}

	const updated = changes.filter(({ type }) => type === 'version') as PackageVersionChange[]
	const keyUpdated = changes.filter(({ type }) => type === 'key') as PackageKeyChange[]
	if (updated.length || keyUpdated.length) {
		result += '### Updated dependencies\n'
		result += updated.map((change) => `* \`${change.name}\` from ${change.fromVersion} to ${change.toVersion}\n`).join('')
		result += keyUpdated.map((change) => `* \`${change.name}\` @ ${change.version} from ${change.fromKey} to ${change.toKey}\n`).join('')
		result += '\n'
	}

	return result + '</details>\n'
}
