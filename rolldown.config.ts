/*
 * SPDX-License-Identifier: MIT
 * SPDX-FileCopyrightText: 2026 Nextcloud GmbH and Nextcloud contributors
 */

import { defineConfig } from 'rolldown'

export default defineConfig({
	platform: 'node',
	input: 'src/index.ts',
	output: {
		esModule: true,
		file: 'dist/index.js',
		format: 'es',
		sourcemap: true,
	},
})
