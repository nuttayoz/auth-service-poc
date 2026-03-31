import { Controller, Get, Res } from '@nestjs/common';
import {
  ApiOkResponse,
  ApiOperation,
  ApiServiceUnavailableResponse,
  ApiTags,
} from '@nestjs/swagger';
import type { Response } from 'express';
import { HealthService } from './health.service.js';
import { HealthReportDto } from './swagger.dto.js';

@Controller('health')
@ApiTags('Health')
export class HealthController {
  constructor(private readonly healthService: HealthService) {}

  @Get()
  @ApiOperation({ summary: 'Get service health for app, Postgres, and Redis' })
  @ApiOkResponse({ type: HealthReportDto })
  @ApiServiceUnavailableResponse({ type: HealthReportDto })
  async getHealth(@Res({ passthrough: true }) res: Response) {
    const report = await this.healthService.getHealthReport();
    res.status(report.status === 'ok' ? 200 : 503);
    return report;
  }
}
