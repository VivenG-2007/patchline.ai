const mongoose = require('mongoose');
const env = require('./env');
const logger = require('./logger');

async function connectDB() {
  mongoose.set('strictQuery', true);
  await mongoose.connect(env.mongoUri, {
    dbName: env.mongoDatabase,
    maxPoolSize: 20,
    serverSelectionTimeoutMS: 10000,
  });
  logger.info('MongoDB connected (auth-service)');
}

module.exports = connectDB;
