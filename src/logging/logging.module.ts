import { Global, Module } from '@nestjs/common';
import { AppLogger } from './app-logger.service.js';
import { LoggingContextService } from './logging-context.service.js';

@Global()
@Module({
  providers: [AppLogger, LoggingContextService],
  exports: [AppLogger, LoggingContextService],
})
export class LoggingModule {}
