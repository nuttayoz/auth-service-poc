import type { EncryptedPayload } from '../crypto/crypto.service.js';

export const ADMIN_SIGNUP_QUEUE = 'admin-signup';
export const ADMIN_SIGNUP_JOB = 'admin-signup.create';

export type AdminSignupJobData = {
  provisioningJobId: string;
  orgName: string;
  orgDomain?: string;
  email: string;
  firstName: string;
  lastName: string;
  userName: string;
  encryptedPassword: EncryptedPayload;
};
