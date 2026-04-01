import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Redis } from 'ioredis';
import { PrismaService } from '../prisma/prisma.service.js';

export type DependencyHealth = {
  status: 'ok' | 'error';
  latencyMs: number;
  error?: string;
};

export type HealthReport = {
  status: 'ok' | 'error';
  timestamp: string;
  uptimeSec: number;
  checks: {
    database: DependencyHealth;
    redis: DependencyHealth;
  };
};

@Injectable()
export class HealthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  async getHealthReport(): Promise<HealthReport> {
    const [database, redis] = await Promise.all([
      this.checkDatabase(),
      this.checkRedis(),
    ]);

    return {
      status:
        database.status === 'ok' && redis.status === 'ok' ? 'ok' : 'error',
      timestamp: new Date().toISOString(),
      uptimeSec: Math.floor(process.uptime()),
      checks: {
        database,
        redis,
      },
    };
  }

  private async checkDatabase(): Promise<DependencyHealth> {
    return this.runCheck(async () => {
      await this.withTimeout(this.prisma.$queryRaw`SELECT 1`, 2000);
    });
  }

  private async checkRedis(): Promise<DependencyHealth> {
    const redisUrl = this.config.get<string>('REDIS_URL');
    if (!redisUrl) {
      return {
        status: 'error',
        latencyMs: 0,
        error: 'REDIS_URL is not configured',
      };
    }

    const client = new Redis(redisUrl, {
      lazyConnect: true,
      maxRetriesPerRequest: 1,
      enableReadyCheck: false,
    });

    try {
      return await this.runCheck(async () => {
        const response = await this.withTimeout(client.ping(), 2000);
        if (response !== 'PONG') {
          throw new Error(
            `Unexpected Redis ping response: ${JSON.stringify(response)}`,
          );
        }
      });
    } finally {
      client.disconnect();
    }
  }

  private async runCheck(
    operation: () => Promise<void>,
  ): Promise<DependencyHealth> {
    const startedAt = Date.now();

    try {
      await operation();
      return {
        status: 'ok',
        latencyMs: Date.now() - startedAt,
      };
    } catch (error) {
      return {
        status: 'error',
        latencyMs: Date.now() - startedAt,
        error:
          error instanceof Error ? error.message : 'Unknown health check error',
      };
    }
  }

  private withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`Health check timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      promise
        .then((value) => {
          clearTimeout(timer);
          resolve(value);
        })
        .catch((error) => {
          clearTimeout(timer);
          reject(error as Error);
        });
    });
  }
}
