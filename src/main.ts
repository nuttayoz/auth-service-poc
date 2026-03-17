import { randomUUID } from 'crypto';
import { NestFactory } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import cookieParser from 'cookie-parser';
import { AppModule } from './app.module.js';
import { AppLogger } from './logging/app-logger.service.js';
import {
  REQUEST_ID_HEADER,
  LoggingContextService,
} from './logging/logging-context.service.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { bufferLogs: true });
  const logger = app.get(AppLogger);
  const loggingContext = app.get(LoggingContextService);

  app.useLogger(logger);
  app.use(cookieParser());
  app.use((req, res, next) => {
    const header = req.headers[REQUEST_ID_HEADER];
    const incoming = Array.isArray(header) ? header[0] : header;
    const requestId =
      typeof incoming === 'string' && incoming.trim().length > 0
        ? incoming.trim()
        : randomUUID();
    const startedAt = Date.now();

    res.setHeader(REQUEST_ID_HEADER, requestId);

    loggingContext.run(
      {
        requestId,
        method: req.method,
        requestPath: req.originalUrl || req.url,
      },
      () => {
        res.on('finish', () => {
          logger.log(
            {
              event: 'http.request.completed',
              method: req.method,
              path: req.originalUrl || req.url,
              statusCode: res.statusCode,
              durationMs: Date.now() - startedAt,
              ip: req.ip,
              userAgent: req.get('user-agent') ?? null,
            },
            'HTTP',
          );
        });

        next();
      },
    );
  });

  const config = app.get(ConfigService);
  const port = config.get<number>('PORT') ?? 3000;
  await app.listen(port);
}
bootstrap();
