import { inspect } from 'util';
import { Injectable, LoggerService } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { LoggingContextService } from './logging-context.service.js';

type LogLevel = 'log' | 'error' | 'warn' | 'debug' | 'verbose' | 'fatal';
type LogFormat = 'json' | 'pretty';

type LogRecord = Record<string, unknown> & {
  timestamp: string;
  level: LogLevel;
  service: string;
  context?: string;
  message: string;
  stack?: string;
};

const PRETTY_EXCLUDED_FIELDS = new Set([
  'timestamp',
  'level',
  'service',
  'context',
  'message',
  'stack',
  'requestId',
  'requestPath',
  'method',
  'jobId',
  'jobName',
  'provisioningJobId',
]);

@Injectable()
export class AppLogger implements LoggerService {
  private readonly format: LogFormat;

  constructor(
    private readonly loggingContext: LoggingContextService,
    private readonly config: ConfigService,
  ) {
    const configuredFormat = this.config.get<LogFormat>('LOG_FORMAT');
    this.format =
      configuredFormat ??
      (this.config.get<string>('NODE_ENV') === 'development'
        ? 'pretty'
        : 'json');
  }

  log(message: unknown, context?: string): void {
    this.write('log', message, context);
  }

  error(message: unknown, stackOrContext?: string, context?: string): void {
    const { stack, resolvedContext } = this.resolveErrorArgs(
      stackOrContext,
      context,
    );
    this.write('error', message, resolvedContext, stack);
  }

  warn(message: unknown, context?: string): void {
    this.write('warn', message, context);
  }

  debug(message: unknown, context?: string): void {
    this.write('debug', message, context);
  }

  verbose(message: unknown, context?: string): void {
    this.write('verbose', message, context);
  }

  fatal(message: unknown, context?: string): void {
    this.write('fatal', message, context);
  }

  private resolveErrorArgs(
    stackOrContext?: string,
    context?: string,
  ): { stack?: string; resolvedContext?: string } {
    if (context) {
      return { stack: stackOrContext, resolvedContext: context };
    }

    if (typeof stackOrContext === 'string' && stackOrContext.includes('\n')) {
      return { stack: stackOrContext };
    }

    return { resolvedContext: stackOrContext };
  }

  private write(
    level: LogLevel,
    message: unknown,
    context?: string,
    stack?: string,
  ): void {
    const normalizedMessage = this.normalizeMessage(message);
    const record: LogRecord = {
      timestamp: new Date().toISOString(),
      level,
      service: 'auth-service',
      ...(context ? { context } : {}),
      ...this.loggingContext.getContext(),
      ...normalizedMessage,
      message:
        typeof normalizedMessage.message === 'string'
          ? normalizedMessage.message
          : String(normalizedMessage.message),
      ...(stack ? { stack } : {}),
    };

    const stream = this.isErrorLevel(level) ? process.stderr : process.stdout;
    const output =
      this.format === 'pretty'
        ? this.formatPretty(record, stream.isTTY)
        : `${JSON.stringify(record)}\n`;

    stream.write(output);
  }

  private isErrorLevel(level: LogLevel): boolean {
    return level === 'error' || level === 'warn' || level === 'fatal';
  }

  private formatPretty(record: LogRecord, useColors: boolean): string {
    const requestId = this.asOptionalString(record.requestId);
    const context = this.asOptionalString(record.context);
    const jobName = this.asOptionalString(record.jobName);
    const jobId = this.asOptionalString(record.jobId);
    const provisioningJobId = this.asOptionalString(record.provisioningJobId);

    const parts = [
      this.colorize(record.timestamp, '90', useColors),
      this.colorize(
        this.levelLabel(record.level),
        this.levelColor(record.level),
        useColors,
      ),
      this.colorize(`[${record.service}]`, '36', useColors),
      ...(context ? [this.colorize(`[${context}]`, '94', useColors)] : []),
      ...(requestId
        ? [this.colorize(`[req:${requestId}]`, '90', useColors)]
        : []),
      ...(jobName || jobId || provisioningJobId
        ? [
            this.colorize(
              `[job:${jobName ?? 'worker'}${jobId ? `#${jobId}` : ''}${
                provisioningJobId ? ` provision:${provisioningJobId}` : ''
              }]`,
              '35',
              useColors,
            ),
          ]
        : []),
      String(record.message),
    ];

    const extras = Object.fromEntries(
      Object.entries(record).filter(
        ([key, value]) =>
          !PRETTY_EXCLUDED_FIELDS.has(key) && value !== undefined,
      ),
    );

    let line = parts.filter(Boolean).join(' ');
    if (Object.keys(extras).length > 0) {
      line += ` ${inspect(extras, {
        colors: useColors,
        depth: 5,
        compact: true,
        breakLength: 140,
      })}`;
    }

    if (typeof record.stack === 'string' && record.stack.length > 0) {
      line += `\n${record.stack}`;
    }

    return `${line}\n`;
  }

  private levelLabel(level: LogLevel): string {
    switch (level) {
      case 'log':
        return 'INFO ';
      case 'warn':
        return 'WARN ';
      case 'error':
        return 'ERROR';
      case 'debug':
        return 'DEBUG';
      case 'verbose':
        return 'VERBO';
      case 'fatal':
        return 'FATAL';
    }
  }

  private levelColor(level: LogLevel): string {
    switch (level) {
      case 'log':
        return '32';
      case 'warn':
        return '33';
      case 'error':
        return '31';
      case 'debug':
        return '34';
      case 'verbose':
        return '35';
      case 'fatal':
        return '41;97';
    }
  }

  private colorize(
    value: string,
    colorCode: string,
    useColors: boolean,
  ): string {
    if (!useColors) {
      return value;
    }

    return `\u001b[${colorCode}m${value}\u001b[0m`;
  }

  private asOptionalString(value: unknown): string | undefined {
    if (typeof value === 'string' && value.length > 0) {
      return value;
    }

    return undefined;
  }

  private normalizeMessage(message: unknown): Record<string, unknown> {
    if (message instanceof Error) {
      return {
        message: message.message,
        stack: message.stack,
        errorName: message.name,
      };
    }

    if (typeof message === 'string') {
      return { message };
    }

    if (message && typeof message === 'object' && !Array.isArray(message)) {
      const value = message as Record<string, unknown>;
      return {
        message:
          typeof value.message === 'string'
            ? value.message
            : typeof value.event === 'string'
              ? value.event
              : 'log',
        ...value,
      };
    }

    return { message: String(message) };
  }
}
