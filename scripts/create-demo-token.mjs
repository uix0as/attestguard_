import { randomUUID } from 'node:crypto';
import jsonwebtoken from 'jsonwebtoken';

const { sign } = jsonwebtoken;

const secret = process.env.JWT_SECRET;
if (!secret || secret.length < 32) {
  throw new Error('Set JWT_SECRET to at least 32 synthetic development characters');
}

const token = sign(
  {
    tenant_id: process.env.DEMO_TENANT_ID ?? 'tenant-demo-synthetic',
    role: process.env.DEMO_ROLE ?? 'security_admin',
    application_id: process.env.DEMO_APPLICATION_ID ?? 'security-console',
  },
  secret,
  {
    algorithm: 'HS256',
    subject: process.env.DEMO_USER_ID ?? 'user-demo-synthetic',
    audience: 'attestguard-api',
    issuer: 'attestguard-dev',
    expiresIn: '15m',
    jwtid: randomUUID(),
  },
);

process.stdout.write(`${token}\n`);
