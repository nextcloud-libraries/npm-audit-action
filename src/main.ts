/**
 * SPDX-FileCopyrightText: 2024 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: MIT
 */
import type { NPMAudit, NPMAuditFix, Vulnerability, VulnerabilityReport } from './npm-audit'

import { exec } from 'node:child_process'
import { writeFile } from 'node:fs/promises'
import { resolve as resolvePath } from 'node:path'
import * as core from '@actions/core'

import 'css.escape'

function isFixable(data: Vulnerability[], vul: Vulnerability): boolean {
	if (vul.fixAvailable !== true) {
		// could be "false" -> not fixable at all
		// or an object -> only with --force
		return false
	}

	// direct dependencies can be fixed
	if (vul.isDirect) {
		return true
	}

	return vul.via.some((via) => {
		if (typeof via !== 'string') {
			// this is a advisatory and no fix available - skip
			return false
		}
		const parent = data.find(({ name }) => name === via)
		return parent && isFixable(data, parent)
	})
}

function getFixable(data: Vulnerability[]) {
	const generalFixable = data.filter((vul) => vul.fixAvailable !== false)
	const fixable = generalFixable.filter((vul) => isFixable(data, vul))
	const forceFixable = generalFixable.filter((vul) => !fixable.includes(vul))

	return {
		fixable,
		forceFixable,
	}
}

function isReport(data: string | VulnerabilityReport): data is VulnerabilityReport {
	return typeof data === 'object' && !!data.title
}

/**
 * Run "npm audit" and return the stdout of that operation
 * @param fix - If "npm audit fix" should be executed
 */
export function runNpmAudit(fix = false): Promise<string> {
	core.debug(`Running npm audit ${fix ? 'fix' : ''}…`)

	return new Promise((resolve, reject) =>
		exec(`npm audit --json ${fix ? 'fix' : ''}`, (error, stdout, stderr) => {
			if (error) {
				core.debug(`[npm audit] Error: ${error.message}`)
			}
			if (stderr) {
				core.debug(`[npm audit]: ${stderr}`)
			}
			if (stdout) {
				core.debug(`[npm audit]: ${stdout}`)
				resolve(stdout.slice(stdout.indexOf('{')))
				return
			}
			reject(error)
		}),
	)
}

/**
 * Format "npm audit --json" output as Markdown
 * @param json - The output JSON string
 * @return Formatted output as markdown
 */
export async function formatNpmAuditOutput(data: NPMAudit): Promise<string> {
	const { fixable, forceFixable } = getFixable(Object.values(data.vulnerabilities))
	core.info(`Found ${fixable.length} fixable issues`)
	if (forceFixable.length) {
		core.info(`And ${forceFixable.length} only fixable manually using --force`)
	}

	let output = '# Audit report\n'
	if (fixable.length === 0) {
		const forceFixableInfo =
			forceFixable.length > 0
				? `, ${forceFixable.length} only fixable manually using --force`
				: ''
		return `No fixable problems found (${Object.values(data.vulnerabilities).length - forceFixable.length} unfixable${forceFixableInfo})`
	}

	output += `
This audit fix resolves ${fixable.length} of the total ${Object.values(data.vulnerabilities).length} vulnerabilities found in your project.

## Updated dependencies
`
	for (const vul of fixable) {
		// we need to encode \ as \\ for Markdown
		output += `* [${vul.name}](#user-content-${CSS.escape(vul.name).replaceAll(/(?<=(^|[^\\]))\\(?!:\\)/g, '\\\\')})\n`
	}

	output += '## Fixed vulnerabilities\n'
	for (const vul of fixable) {
		const info = vul.via.find(isReport)
		output += `\n### \`${vul.name}\` <a href="#user-content-${CSS.escape(vul.name)}" id="${CSS.escape(vul.name)}">#</a>\n`

		if (info) {
			const cvss = info.cvss?.score ? ` (CVSS ${info.cvss?.score})` : ''
			output += `* ${info.title}\n`
			output += `* Severity: **${info.severity}**${info.severity === 'critical' ? ' 🚨' : ''}${cvss}\n`
			output += `* Reference: [${info.url}](${info.url})\n`
		} else {
			output += `* Caused by vulnerable dependency:\n`
			for (const via of vul.via as string[]) {
				output += `  * [${via}](#user-content-${CSS.escape(via)})\n`
			}
		}
		output += `* Affected versions: ${vul.range}\n`
		output += '* Package usage:\n'
		for (const node of vul.nodes) {
			output += `  * \`${node}\`\n`
		}
	}
	return output
}

// Typescript helper
function isNPMAuditFix(data: NPMAudit | NPMAuditFix): data is NPMAuditFix {
	return 'audit' in data
}

/**
 * The main function for the action.
 * @returns Promise that resolves when the action is complete.
 */
export async function run(): Promise<void> {
	try {
		const wd =
			core.getInput('working-directory', { required: false }) ||
			process.env.GITHUB_WORKSPACE
		const outputPath = core.getInput('output-path', { required: false })
		const fix = core.getBooleanInput('fix', { required: false })

		// Setup environment by switching the working directory
		const resolvedWD = resolvePath(wd)
		core.debug(`Setting working directory to "${resolvedWD}".`)
		process.chdir(resolvedWD)

		const output = await runNpmAudit()
		let data: NPMAudit | NPMAuditFix = JSON.parse(output)
		if (isNPMAuditFix(data)) {
			data = data as NPMAuditFix
			// Print some information
			core.info(`[npm audit] Added   ${data.added} packages`)
			core.info(`[npm audit] Removed ${data.removed} packages`)
			core.info(`[npm audit] Changed ${data.changed} packages`)
			core.info(`[npm audit] Audited ${data.audited} packages`)
			// Set data to the audit report
			data = data.audit
		}

		const issues = Object.values(data.vulnerabilities)
		const totalIssues = issues.length
		const { fixable, forceFixable } = getFixable(issues)
		core.setOutput('issues-total', totalIssues)
		core.setOutput('issues-fixable', fixable.length)
		core.setOutput('issues-force-fixable', forceFixable.length)
		core.setOutput('issues-unfixable', totalIssues - fixable.length - forceFixable.length)

		const formattedOutput = await formatNpmAuditOutput(data)
		core.setOutput('markdown', formattedOutput)

		if (outputPath) {
			const resolvedPath = resolvePath(outputPath)
			if (!resolvedPath.startsWith(resolvePath(process.env.GITHUB_WORKSPACE))) {
				core.setFailed('Invalid "output-path"')
				return
			}
			await writeFile(resolvedPath, formattedOutput)
		}

		if (fix) {
			core.info('Running `npm audit` with `fix` flag')
			await runNpmAudit(true)
		}
	} catch (error) {
		// Fail the workflow run if an error occurs
		core.setFailed(error.message)
	}
}
