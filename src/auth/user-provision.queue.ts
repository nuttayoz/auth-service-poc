import type { EncryptedPayload } from '../crypto/crypto.service.js';

export const USER_PROVISION_QUEUE = 'user-provision';
export const USER_PROVISION_JOB = 'user-provision.create';

export type UserProvisionJobData = {
  requestId?: string;
  provisioningJobId: string;
  orgId: string;
  requestedByUserId?: string;
  requestedByRootKeyId?: string;
  email: string;
  firstName: string;
  lastName: string;
  userName: string;
  role: 'ROOT' | 'USER';
  encryptedPassword: EncryptedPayload;
};
