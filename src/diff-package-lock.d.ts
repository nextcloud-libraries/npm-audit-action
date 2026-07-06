/**
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: MIT
 */

declare module 'diff-package-lock/dist/Tree.js' {
	export interface PackageChange {
		type: 'add' | 'remove'
		key: string
		name: string
		version: string
	}

	export interface PackageVersionChange {
		type: 'version'
		name: string
		key: string
		fromVersion: string
		toVersion: string
	}

	export interface PackageKeyChange {
		type: 'key'
		name: string
		version: string
		fromKey: string
		toKey: string
	}

	export type Change = PackageChange | PackageVersionChange | PackageKeyChange

	interface TreeChange {
		toJSON(): Change
	}

	interface Tree {
		getChanges(other: Tree): Promise<TreeChange[]>
	}

	interface TreeConstructor {
		/**
		 * @param treeish - Git tree-ish to read the lock file from, or "disk" for the working tree
		 * @param options - Options
		 * @param options.cwd - Directory containing the lock file
		 */
		new (treeish: string, options: { cwd: string }): Tree
	}

	// CommonJS module with `exports.default`: Node.js imports it as `{ default: Tree }`, Vitest unwraps it to `Tree`
	const module: { default: TreeConstructor } | TreeConstructor
	export default module
}
