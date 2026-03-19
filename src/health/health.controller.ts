import { Controller, Get, Res } from '@nestjs/common';
import type { Response } from 'express';
import { HealthService } from './health.service.js';

@Controller('health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  async getHealth(@Res({ passthrough: true }) res: Response) {
    const report = await this.healthService.getHealthReport();
    res.status(report.status === 'ok' ? 200 : 503);
    return report;
  }
}
