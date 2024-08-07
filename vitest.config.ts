/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: MIT
 */
import { defineConfig } from 'vite'

export default defineConfig({
	test: {
		coverage: {
			provider: 'v8',
			reporter: ['json-summary', 'text'],
		},
	},
})
