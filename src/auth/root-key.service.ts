import { createHash, randomBytes } from 'crypto';
import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  NotFoundException,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { Prisma, RootKey, RootKeyStatus } from '@prisma/client';
import type { EncryptedPayload } from '../crypto/crypto.service.js';
import { CryptoService } from '../crypto/crypto.service.js';
import { PrismaService } from '../prisma/prisma.service.js';

export type RootKeySummary = {
  id: string;
  orgId: string;
  createdByUserId: string | null;
  status: RootKeyStatus;
  lastUsedAt: Date | null;
  createdAt: Date;
  revokedAt: Date | null;
};

export type RootKeyIssueResponse = RootKeySummary & {
  key: string;
};

@Injectable()
export class RootKeyService {
  private readonly logger = new Logger(RootKeyService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly crypto: CryptoService,
  ) {}

  async listRootKeys(orgId: string): Promise<RootKeySummary[]> {
    this.assertOrgId(orgId);

    const keys = await this.prisma.rootKey.findMany({
      where: { orgId },
      orderBy: { createdAt: 'desc' },
    });

    return keys.map((key) => this.toSummary(key));
  }

  async createRootKey(
    actorUserId: string,
    orgId: string,
  ): Promise<RootKeyIssueResponse> {
    this.assertCryptoEnabled();
    this.assertOrgId(orgId);

    const activeKey = await this.prisma.rootKey.findFirst({
      where: {
        orgId,
        status: RootKeyStatus.ACTIVE,
      },
      select: { id: true },
    });
    if (activeKey) {
      throw new ConflictException(
        `An active root key already exists for this org (rootKeyId: ${activeKey.id})`,
      );
    }

    const issuedKey = this.generateRootKey();
    let created: RootKey;
    try {
      created = await this.prisma.rootKey.create({
        data: {
          orgId,
          createdByUserId: actorUserId,
          keyHash: this.hashRootKey(issuedKey),
          keyEnc: this.serializeEncryptedPayload(
            this.crypto.encrypt(issuedKey),
          ),
          status: RootKeyStatus.ACTIVE,
        },
      });
    } catch (error) {
      if (
        error instanceof Prisma.PrismaClientKnownRequestError &&
        error.code === 'P2002'
      ) {
        throw new ConflictException(
          'An active root key already exists for this org',
        );
      }
      throw error;
    }

    await this.writeAuditLogSafe(actorUserId, 'root_key.create', {
      rootKeyId: created.id,
      orgId,
    });

    return {
      ...this.toSummary(created),
      key: issuedKey,
    };
  }

  async rotateRootKey(
    rootKeyId: string,
    actorUserId: string,
    orgId: string,
  ): Promise<RootKeyIssueResponse> {
    this.assertCryptoEnabled();
    this.assertOrgId(orgId);

    const existing = await this.findOrgRootKey(rootKeyId, orgId);
    if (existing.status !== RootKeyStatus.ACTIVE) {
      throw new ConflictException('Root key is not active');
    }

    const issuedKey = this.generateRootKey();
    const now = new Date();

    const next = await this.prisma.$transaction(async (tx) => {
      await tx.rootKey.update({
        where: { id: rootKeyId },
        data: {
          status: RootKeyStatus.REVOKED,
          revokedAt: now,
        },
      });

      const created = await tx.rootKey.create({
        data: {
          orgId,
          createdByUserId: actorUserId,
          keyHash: this.hashRootKey(issuedKey),
          keyEnc: this.serializeEncryptedPayload(
            this.crypto.encrypt(issuedKey),
          ),
          status: RootKeyStatus.ACTIVE,
        },
      });

      await tx.auditLog.create({
        data: {
          actorUserId,
          action: 'root_key.rotate',
          metadata: {
            previousRootKeyId: rootKeyId,
            rootKeyId: created.id,
            orgId,
          } as Prisma.InputJsonValue,
        },
      });

      return created;
    });

    return {
      ...this.toSummary(next),
      key: issuedKey,
    };
  }

  async revokeRootKey(
    rootKeyId: string,
    actorUserId: string,
    orgId: string,
  ): Promise<RootKeySummary> {
    this.assertOrgId(orgId);

    const existing = await this.findOrgRootKey(rootKeyId, orgId);
    if (existing.status !== RootKeyStatus.ACTIVE) {
      throw new ConflictException('Root key is not active');
    }

    const revoked = await this.prisma.rootKey.update({
      where: { id: rootKeyId },
      data: {
        status: RootKeyStatus.REVOKED,
        revokedAt: new Date(),
      },
    });

    await this.writeAuditLogSafe(actorUserId, 'root_key.revoke', {
      rootKeyId,
      orgId,
    });

    return this.toSummary(revoked);
  }

  async validateRootKey(rawKey: string): Promise<RootKeySummary> {
    const key = rawKey.trim();
    if (!key) {
      throw new UnauthorizedException('Missing root key');
    }

    const rootKey = await this.prisma.rootKey.findFirst({
      where: {
        keyHash: this.hashRootKey(key),
        status: RootKeyStatus.ACTIVE,
      },
    });

    if (!rootKey) {
      throw new UnauthorizedException('Invalid root key');
    }

    const updated = await this.prisma.rootKey.update({
      where: { id: rootKey.id },
      data: { lastUsedAt: new Date() },
    });

    return this.toSummary(updated);
  }

  private async findOrgRootKey(
    rootKeyId: string,
    orgId: string,
  ): Promise<RootKey> {
    const existing = await this.prisma.rootKey.findUnique({
      where: { id: rootKeyId },
    });

    if (!existing || existing.orgId !== orgId) {
      throw new NotFoundException('Root key not found');
    }

    return existing;
  }

  private generateRootKey(): string {
    return `rk_${randomBytes(32).toString('base64url')}`;
  }

  private hashRootKey(key: string): string {
    return createHash('sha256').update(key, 'utf8').digest('hex');
  }

  private serializeEncryptedPayload(
    payload: EncryptedPayload,
  ): Uint8Array<ArrayBuffer> {
    const encoded = Buffer.from(JSON.stringify(payload), 'utf8');
    const bytes = new Uint8Array<ArrayBuffer>(new ArrayBuffer(encoded.length));
    bytes.set(encoded);
    return bytes;
  }

  private toSummary(rootKey: RootKey): RootKeySummary {
    return {
      id: rootKey.id,
      orgId: rootKey.orgId,
      createdByUserId: rootKey.createdByUserId ?? null,
      status: rootKey.status,
      lastUsedAt: rootKey.lastUsedAt ?? null,
      createdAt: rootKey.createdAt,
      revokedAt: rootKey.revokedAt ?? null,
    };
  }

  private assertCryptoEnabled(): void {
    if (!this.crypto.isEnabled()) {
      throw new ServiceUnavailableException('Crypto is disabled');
    }
  }

  private assertOrgId(orgId: string | undefined): void {
    if (!orgId) {
      throw new BadRequestException('Missing org');
    }
  }

  private async writeAuditLogSafe(
    actorUserId: string | null,
    action: string,
    metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.prisma.auditLog.create({
        data: {
          actorUserId,
          action,
          metadata: metadata as Prisma.InputJsonValue,
        },
      });
    } catch (error) {
      this.logger.warn(
        `Audit log write failed for action "${action}": ${error instanceof Error ? error.message : 'unknown error'}`,
      );
    }
  }
}
