export function createBullConnection(redisUrl: string) {
  const url = new URL(redisUrl);
  const db = url.pathname.length > 1 ? Number(url.pathname.slice(1)) : 0;

  return {
    host: url.hostname,
    port: Number(url.port || 6379),
    ...(url.username ? { username: decodeURIComponent(url.username) } : {}),
    ...(url.password ? { password: decodeURIComponent(url.password) } : {}),
    ...(Number.isNaN(db) ? {} : { db }),
    ...(url.protocol === 'rediss:' ? { tls: {} } : {}),
  };
}
