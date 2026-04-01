import { Injectable } from '@nestjs/common';
import { AsyncLocalStorage } from 'async_hooks';

export const REQUEST_ID_HEADER = 'x-request-id';

export type LogContext = {
  requestId?: string;
  requestPath?: string;
  method?: string;
  jobId?: string;
  jobName?: string;
  provisioningJobId?: string;
};

@Injectable()
export class LoggingContextService {
  private readonly storage = new AsyncLocalStorage<LogContext>();

  run<T>(context: LogContext, callback: () => T): T {
    const current = this.storage.getStore() ?? {};
    return this.storage.run({ ...current, ...context }, callback);
  }

  getContext(): LogContext {
    return { ...(this.storage.getStore() ?? {}) };
  }

  get<K extends keyof LogContext>(key: K): LogContext[K] | undefined {
    return this.storage.getStore()?.[key];
  }
}
