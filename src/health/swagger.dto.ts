import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class DependencyHealthDto {
  @ApiProperty({ enum: ['ok', 'error'] })
  status!: 'ok' | 'error';

  @ApiProperty({ example: 12 })
  latencyMs!: number;

  @ApiPropertyOptional({
    nullable: true,
    example: 'REDIS_URL is not configured',
  })
  error?: string;
}

export class HealthChecksDto {
  @ApiProperty({ type: () => DependencyHealthDto })
  database!: DependencyHealthDto;

  @ApiProperty({ type: () => DependencyHealthDto })
  redis!: DependencyHealthDto;
}

export class HealthReportDto {
  @ApiProperty({ enum: ['ok', 'error'] })
  status!: 'ok' | 'error';

  @ApiProperty({ type: String, format: 'date-time' })
  timestamp!: string;

  @ApiProperty({ example: 12345 })
  uptimeSec!: number;

  @ApiProperty({ type: () => HealthChecksDto })
  checks!: HealthChecksDto;
}
