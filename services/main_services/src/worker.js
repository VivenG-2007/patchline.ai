// Standalone entrypoint for running the BullMQ scan/fix workers as their own
// process/container, separate from the Express API. Use this (with
// DISABLE_INLINE_WORKERS=true on the API instance) once you want scanner
// workers to scale independently of the API — see docs/architecture.md.
//
//   node src/worker.js
//
require('dotenv').config();
const logger = require('./config/logger');
const { startWorkers } = require('./workers/scannerWorkers');

logger.info('Starting standalone BullMQ worker process (scan + fix queues)');
const { scanWorker, fixWorker } = startWorkers();

const shutdown = async (signal) => {
    logger.info(`${signal} received, shutting down worker process`);
    try {
        await Promise.all([scanWorker.close(), fixWorker.close()]);
    } finally {
        process.exit(0);
    }
};
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
