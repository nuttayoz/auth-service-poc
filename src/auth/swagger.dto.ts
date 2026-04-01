import {
  ProvisioningJobStatus,
  RootKeyStatus,
  UserOrgAccessSource,
  UserRole,
} from '@prisma/client';
import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';

export class AdminSignupRequestDto {
  @ApiProperty({ example: 'Acme Corp' })
  orgName?: string;

  @ApiPropertyOptional({ example: 'acme.com' })
  orgDomain?: string;

  @ApiProperty({ example: 'admin@acme.com' })
  email?: string;

  @ApiProperty({ example: 'Secret123!' })
  password?: string;

  @ApiPropertyOptional({ example: 'Acme' })
  firstName?: string;

  @ApiPropertyOptional({ example: 'Admin' })
  lastName?: string;

  @ApiPropertyOptional({ example: 'admin@acme.com' })
  userName?: string;
}

export class AdminSignupJobResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiPropertyOptional({ nullable: true, example: 'Acme Corp' })
  orgName!: string | null;

  @ApiPropertyOptional({ nullable: true, example: 'acme.com' })
  orgDomain!: string | null;

  @ApiPropertyOptional({ nullable: true, example: '363895632827514883' })
  orgId!: string | null;

  @ApiProperty({ example: 'admin@acme.com' })
  email!: string;

  @ApiProperty({ example: 'admin@acme.com' })
  userName!: string;

  @ApiProperty({ enum: UserRole, enumName: 'UserRole' })
  role!: UserRole;

  @ApiProperty({
    enum: ProvisioningJobStatus,
    enumName: 'ProvisioningJobStatus',
  })
  status!: ProvisioningJobStatus;

  @ApiPropertyOptional({ nullable: true, format: 'uuid' })
  resultUserId!: string | null;

  @ApiPropertyOptional({ nullable: true })
  errorMessage!: string | null;

  @ApiProperty({ type: String, format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ type: String, format: 'date-time' })
  updatedAt!: Date;

  @ApiPropertyOptional({ nullable: true, type: String, format: 'date-time' })
  startedAt!: Date | null;

  @ApiPropertyOptional({ nullable: true, type: String, format: 'date-time' })
  completedAt!: Date | null;
}

export class CreateUserRequestDto {
  @ApiProperty({ example: 'user@acme.com' })
  email?: string;

  @ApiProperty({ example: 'Secret123!' })
  password?: string;

  @ApiPropertyOptional({ example: 'Franky' })
  firstName?: string;

  @ApiPropertyOptional({ example: 'Tester' })
  lastName?: string;

  @ApiPropertyOptional({ example: 'user@acme.com' })
  userName?: string;

  @ApiPropertyOptional({ enum: UserRole, enumName: 'RequestedUserRole' })
  role?: 'ROOT' | 'USER';
}

export class ProvisioningJobResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiPropertyOptional({ nullable: true, example: '363895632827514883' })
  orgId!: string | null;

  @ApiProperty({ example: 'user@acme.com' })
  email!: string;

  @ApiProperty({ example: 'user@acme.com' })
  userName!: string;

  @ApiProperty({ enum: UserRole, enumName: 'UserRole' })
  role!: UserRole;

  @ApiProperty({
    enum: ProvisioningJobStatus,
    enumName: 'ProvisioningJobStatus',
  })
  status!: ProvisioningJobStatus;

  @ApiPropertyOptional({ nullable: true, format: 'uuid' })
  resultUserId!: string | null;

  @ApiPropertyOptional({ nullable: true })
  errorMessage!: string | null;

  @ApiProperty({ type: String, format: 'date-time' })
  createdAt!: Date;

  @ApiProperty({ type: String, format: 'date-time' })
  updatedAt!: Date;

  @ApiPropertyOptional({ nullable: true, type: String, format: 'date-time' })
  startedAt!: Date | null;

  @ApiPropertyOptional({ nullable: true, type: String, format: 'date-time' })
  completedAt!: Date | null;
}

export class SessionResponseDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ example: '364328517313232899' })
  userId!: string;

  @ApiPropertyOptional({ nullable: true, example: '364328517313232899' })
  homeOrgId!: string | null;

  @ApiPropertyOptional({ nullable: true, example: '364459161343229955' })
  activeOrgId!: string | null;

  @ApiPropertyOptional({ nullable: true, example: '364459161343229955' })
  orgId!: string | null;

  @ApiPropertyOptional({
    nullable: true,
    enum: UserOrgAccessSource,
    enumName: 'UserOrgAccessSource',
  })
  accessSource?: UserOrgAccessSource;

  @ApiProperty({ type: [String], example: ['USER'] })
  roles!: string[];

  @ApiProperty({ type: [String], example: [] })
  permissions!: string[];

  @ApiProperty({ type: String, format: 'date-time' })
  accessExpiresAt!: Date;

  @ApiProperty({ example: false })
  accessExpired!: boolean;
}

export class CallbackSessionResponseDto {
  @ApiProperty({ format: 'uuid' })
  sessionId!: string;

  @ApiProperty({ example: '364328517313232899' })
  userId!: string;

  @ApiPropertyOptional({ nullable: true, example: '364328517313232899' })
  homeOrgId!: string | null;

  @ApiPropertyOptional({ nullable: true, example: '364459161343229955' })
  activeOrgId!: string | null;

  @ApiPropertyOptional({ nullable: true, example: '364459161343229955' })
  orgId!: string | null;

  @ApiProperty({
    enum: UserOrgAccessSource,
    enumName: 'UserOrgAccessSource',
    example: UserOrgAccessSource.DIRECT,
  })
  accessSource!: UserOrgAccessSource;

  @ApiProperty({ type: [String], example: ['ROOT'] })
  roles!: string[];
}

export class SwitchActiveOrgRequestDto {
  @ApiProperty({ example: '364459161343229955' })
  orgId?: string;
}

export class RootKeySummaryDto {
  @ApiProperty({ format: 'uuid' })
  id!: string;

  @ApiProperty({ example: '364459161343229955' })
  orgId!: string;

  @ApiPropertyOptional({ nullable: true, example: '364328517313232899' })
  createdByUserId!: string | null;

  @ApiProperty({ enum: RootKeyStatus, enumName: 'RootKeyStatus' })
  status!: RootKeyStatus;

  @ApiPropertyOptional({ nullable: true, type: String, format: 'date-time' })
  lastUsedAt!: Date | null;

  @ApiProperty({ type: String, format: 'date-time' })
  createdAt!: Date;

  @ApiPropertyOptional({ nullable: true, type: String, format: 'date-time' })
  revokedAt!: Date | null;
}

export class RootKeyIssueResponseDto extends RootKeySummaryDto {
  @ApiProperty({
    example:
      'rk_9f8a2b89f6fd9a6b9e52d9bd0b91f743f53c5e6ca8792a8a4fd43802eab0b1aa',
  })
  key!: string;
}
