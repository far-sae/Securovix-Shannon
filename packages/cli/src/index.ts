import { program } from 'commander';
import chalk from 'chalk';
import { detectMode } from './modes/detect.js';
import { runScan } from './docker/orchestrator.js';
import { loadConfig } from './config/loader.js';

program
  .name('shannon')
  .description('Autonomous white-box penetration testing framework')
  .version('0.0.0');

program
  .command('scan')
  .description('Run a penetration test against a target')
  .requiredOption('-c, --config <path>', 'Path to shannon.yaml config file')
  .option('-r, --resume', 'Resume a previous scan session')
  .option('--workspace <path>', 'Override workspace directory')
  .action(async (opts) => {
    try {
      const mode = detectMode();
      console.log(chalk.blue(`Shannon starting in ${mode.type} mode...`));

      const config = await loadConfig(opts.config);
      await runScan({ mode, config, resume: opts.resume ?? false, workspaceOverride: opts.workspace });
    } catch (err) {
      console.error(chalk.red(`Fatal: ${err instanceof Error ? err.message : String(err)}`));
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show status of a running or completed scan')
  .option('--workspace <path>', 'Workspace directory')
  .action(async (opts) => {
    const mode = detectMode();
    const wsDir = opts.workspace ?? mode.workspacesDir;
    console.log(chalk.blue(`Checking scan status in ${wsDir}...`));
    // Status will read session.json from workspace
  });

program.parse();
