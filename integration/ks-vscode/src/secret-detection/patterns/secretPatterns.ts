// Base interface for common secret pattern properties
export interface BaseSecretPattern {
  pattern: RegExp;
  description: string;
  confidence: 'high' | 'medium' | 'low';
}

// Secret pattern interface extending base interface
export interface SecretPattern extends BaseSecretPattern {
  type: string;
}

// Secret key pattern interface extending base interface
export interface SecretKeyPattern extends BaseSecretPattern {
}

// High-confidence secret patterns (very specific formats)
export const HIGH_CONFIDENCE_PATTERNS: SecretPattern[] = [
  // Stripe Keys
  {
    pattern: /^sk_[a-zA-Z0-9]{24}$/,
    type: 'stripe_secret_key',
    description: 'Stripe secret key',
    confidence: 'high',
  },
  {
    pattern: /^pk_[a-zA-Z0-9]{24}$/,
    type: 'stripe_publishable_key',
    description: 'Stripe publishable key',
    confidence: 'high',
  },

  // AWS Keys
  {
    pattern: /^AKIA[0-9A-Z]{16}$/,
    type: 'aws_access_key',
    description: 'AWS access key ID',
    confidence: 'high',
  },
  {
    pattern: /^[0-9a-zA-Z/+]{40}$/,
    type: 'aws_secret_key',
    description: 'AWS secret access key',
    confidence: 'high',
  },

  // Azure Keys
  {
    pattern: /^[a-zA-Z0-9]{32}$/,
    type: 'azure_storage_key',
    description: 'Azure storage account key',
    confidence: 'high',
  },

  // Google Cloud
  {
    pattern: /^ya29\.[0-9A-Za-z\-_]+$/,
    type: 'google_oauth_token',
    description: 'Google OAuth token',
    confidence: 'high',
  },
  {
    pattern: /^AIza[0-9A-Za-z\-_]{35}$/,
    type: 'google_api_key',
    description: 'Google API key',
    confidence: 'high',
  },

  // GitHub/GitLab
  {
    pattern: /^gh[oprst]_[A-Za-z0-9_]{36}$/,
    type: 'github_token',
    description: 'GitHub personal access token',
    confidence: 'high',
  },
  {
    pattern: /^glpat-[A-Za-z0-9_-]{20}$/,
    type: 'gitlab_token',
    description: 'GitLab personal access token',
    confidence: 'high',
  },

  // JWT Tokens
  {
    pattern: /^eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+$/,
    type: 'jwt_token',
    description: 'JWT token',
    confidence: 'high',
  },

  // UUIDs
  {
    pattern: /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    type: 'uuid',
    description: 'UUID/GUID',
    confidence: 'high',
  },

  // Slack Webhooks
  {
    pattern:
      /^https:\/\/hooks\.slack\.com\/services\/[A-Z0-9]+\/[A-Z0-9]+\/[a-zA-Z0-9]+$/,
    type: 'slack_webhook',
    description: 'Slack webhook URL',
    confidence: 'high',
  },

  // Discord Webhooks
  {
    pattern: /^https:\/\/discord\.com\/api\/webhooks\/\d+\/[a-zA-Z0-9_-]+$/,
    type: 'discord_webhook',
    description: 'Discord webhook URL',
    confidence: 'high',
  },
];

// Medium-confidence secret patterns (common formats)
export const MEDIUM_CONFIDENCE_PATTERNS: SecretPattern[] = [
  // Generic API keys (32+ characters)
  {
    pattern: /^[a-zA-Z0-9]{32,}$/,
    type: 'api_key',
    description: 'Generic API key (32+ chars)',
    confidence: 'medium',
  },

  // Bearer tokens
  {
    pattern: /^Bearer\s+[a-zA-Z0-9._-]+$/,
    type: 'bearer_token',
    description: 'Bearer token',
    confidence: 'medium',
  },

  // Base64 encoded secrets
  {
    pattern: /^[A-Za-z0-9+/]{20,}={0,2}$/,
    type: 'base64_secret',
    description: 'Base64 encoded secret',
    confidence: 'medium',
  },

  // Hex encoded secrets
  {
    pattern: /^[0-9a-fA-F]{32,}$/,
    type: 'hex_secret',
    description: 'Hex encoded secret',
    confidence: 'medium',
  },

  // Database URLs
  {
    pattern:
      /^(mongodb|postgresql|mysql|redis|sqlite):\/\/[^@]+@[^:]+:\d+\/[^?]+/,
    type: 'database_url',
    description: 'Database connection URL',
    confidence: 'medium',
  },
  {
    pattern: /^[a-zA-Z]+:\/\/[^@]+@[^:]+:\d+\//,
    type: 'database_url',
    description: 'Generic database URL',
    confidence: 'medium',
  },

  // Docker registry passwords
  {
    pattern: /^[a-zA-Z0-9._-]+:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+$/,
    type: 'docker_auth',
    description: 'Docker registry authentication',
    confidence: 'medium',
  },

  // SSH Private Keys
  {
    pattern: /^-----BEGIN\s+(RSA|DSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/,
    type: 'ssh_private_key',
    description: 'SSH private key',
    confidence: 'medium',
  },

  // SSL/TLS Certificates
  {
    pattern:
      /^-----BEGIN\s+(CERTIFICATE|PRIVATE\s+KEY|RSA\s+PRIVATE\s+KEY)-----/,
    type: 'ssl_certificate',
    description: 'SSL/TLS certificate or private key',
    confidence: 'medium',
  },

  // Payment Gateway Keys
  {
    pattern: /^[a-zA-Z0-9]{24,}$/,
    type: 'payment_gateway_key',
    description: 'Payment gateway API key',
    confidence: 'medium',
  },

  // Message Queue URLs
  {
    pattern: /^(amqp|mqtt|redis):\/\/[^@]+@[^:]+:\d+/,
    type: 'message_queue_url',
    description: 'Message queue connection URL',
    confidence: 'medium',
  },

  // Kubernetes Secrets
  {
    pattern: /^[a-zA-Z0-9+/]{32,}={0,2}$/,
    type: 'kubernetes_secret',
    description: 'Kubernetes base64 encoded secret',
    confidence: 'medium',
  },
];

// Low-confidence secret patterns (generic but suspicious)
export const LOW_CONFIDENCE_PATTERNS: SecretPattern[] = [
  // Generic passwords (8+ characters)
  {
    pattern: /^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]{8,}$/,
    type: 'password',
    description: 'Generic password (8+ chars)',
    confidence: 'low',
  },

  // Generic tokens (16+ characters)
  {
    pattern: /^[a-zA-Z0-9._-]{16,}$/,
    type: 'generic_token',
    description: 'Generic token (16+ chars)',
    confidence: 'low',
  },

  // Email-like patterns that might be secrets
  {
    pattern: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
    type: 'email_like_secret',
    description: 'Email-like pattern that might be a secret',
    confidence: 'low',
  },
];

// All patterns combined
export const ALL_SECRET_PATTERNS = [
  ...HIGH_CONFIDENCE_PATTERNS,
  ...MEDIUM_CONFIDENCE_PATTERNS,
  ...LOW_CONFIDENCE_PATTERNS,
];

// Enhanced secret key patterns (keys that suggest secret values)
export const SECRET_KEY_PATTERNS: SecretKeyPattern[] = [
  // High confidence keys
  { pattern: /api[_-]?key/i, description: 'API key', confidence: 'high' },
  { pattern: /secret/i, description: 'Secret', confidence: 'high' },
  { pattern: /password/i, description: 'Password', confidence: 'high' },
  { pattern: /token/i, description: 'Token', confidence: 'high' },
  { pattern: /access[_-]?key/i, description: 'Access key', confidence: 'high' },
  { pattern: /secret[_-]?key/i, description: 'Secret key', confidence: 'high' },
  {
    pattern: /client[_-]?secret/i,
    description: 'Client secret',
    confidence: 'high',
  },
  { pattern: /app[_-]?secret/i, description: 'App secret', confidence: 'high' },
  {
    pattern: /private[_-]?key/i,
    description: 'Private key',
    confidence: 'high',
  },
  { pattern: /webhook/i, description: 'Webhook', confidence: 'high' },

  // Medium confidence keys
  { pattern: /key/i, description: 'Key', confidence: 'medium' },
  { pattern: /auth/i, description: 'Authentication', confidence: 'medium' },
  { pattern: /credential/i, description: 'Credential', confidence: 'medium' },
  { pattern: /private/i, description: 'Private', confidence: 'medium' },
  { pattern: /signature/i, description: 'Signature', confidence: 'medium' },
  { pattern: /salt/i, description: 'Salt', confidence: 'medium' },
  { pattern: /hash/i, description: 'Hash', confidence: 'medium' },
  { pattern: /certificate/i, description: 'Certificate', confidence: 'medium' },
  { pattern: /encryption/i, description: 'Encryption', confidence: 'medium' },
  { pattern: /cipher/i, description: 'Cipher', confidence: 'medium' },
  {
    pattern: /db[_-]?password/i,
    description: 'Database password',
    confidence: 'medium',
  },
  {
    pattern: /database[_-]?url/i,
    description: 'Database URL',
    confidence: 'medium',
  },
  {
    pattern: /connection[_-]?string/i,
    description: 'Connection string',
    confidence: 'medium',
  },
  {
    pattern: /redis[_-]?password/i,
    description: 'Redis password',
    confidence: 'medium',
  },
  {
    pattern: /mongodb[_-]?uri/i,
    description: 'MongoDB URI',
    confidence: 'medium',
  },
  {
    pattern: /postgres[_-]?password/i,
    description: 'PostgreSQL password',
    confidence: 'medium',
  },
  {
    pattern: /mysql[_-]?password/i,
    description: 'MySQL password',
    confidence: 'medium',
  },
  {
    pattern: /aws[_-]?secret/i,
    description: 'AWS secret',
    confidence: 'medium',
  },
  { pattern: /azure[_-]?key/i, description: 'Azure key', confidence: 'medium' },
  {
    pattern: /gcp[_-]?key/i,
    description: 'Google Cloud key',
    confidence: 'medium',
  },
  {
    pattern: /docker[_-]?password/i,
    description: 'Docker password',
    confidence: 'medium',
  },
  {
    pattern: /kubernetes[_-]?secret/i,
    description: 'Kubernetes secret',
    confidence: 'medium',
  },
  {
    pattern: /slack[_-]?webhook/i,
    description: 'Slack webhook',
    confidence: 'medium',
  },
  {
    pattern: /discord[_-]?webhook/i,
    description: 'Discord webhook',
    confidence: 'medium',
  },
  {
    pattern: /github[_-]?token/i,
    description: 'GitHub token',
    confidence: 'medium',
  },
  {
    pattern: /gitlab[_-]?token/i,
    description: 'GitLab token',
    confidence: 'medium',
  },
  {
    pattern: /stripe[_-]?key/i,
    description: 'Stripe key',
    confidence: 'medium',
  },
  {
    pattern: /paypal[_-]?key/i,
    description: 'PayPal key',
    confidence: 'medium',
  },
];

// Enhanced placeholder patterns (values that should be ignored)
export const PLACEHOLDER_PATTERNS = [
  /^<.*>$/,
  /^\[.*\]$/,
  /^\{.*\}$/,
  /^placeholder$/i,
  /^example$/i,
  /^your_.*$/i,
  /^enter_.*$/i,
  /^test.*$/i,
  /^demo.*$/i,
  /^sample.*$/i,
  /^temp.*$/i,
  /^fake.*$/i,
  /^mock.*$/i,
  /^xxx.*$/i,
  /^123.*$/,
  /^password.*$/i,
  /^secret.*$/i,
  /^api_key.*$/i,
  /^token.*$/i,
  /^key.*$/i,
  /^auth.*$/i,
  /^credential.*$/i,
  /^private.*$/i,
  /^signature.*$/i,
  /^salt.*$/i,
  /^hash.*$/i,
  /^certificate.*$/i,
  /^encryption.*$/i,
  /^cipher.*$/i,
  /^db_password.*$/i,
  /^database_url.*$/i,
  /^connection_string.*$/i,
  /^redis_password.*$/i,
  /^mongodb_uri.*$/i,
  /^postgres_password.*$/i,
  /^mysql_password.*$/i,
  /^aws_secret.*$/i,
  /^azure_key.*$/i,
  /^gcp_key.*$/i,
  /^docker_password.*$/i,
  /^kubernetes_secret.*$/i,
  /^slack_webhook.*$/i,
  /^discord_webhook.*$/i,
  /^github_token.*$/i,
  /^gitlab_token.*$/i,
  /^stripe_key.*$/i,
  /^paypal_key.*$/i,
];

// Utility functions remain the same
export function isSecretValue(
  value: string,
  minConfidence: 'high' | 'medium' | 'low' = 'low'
): boolean {
  const confidenceLevels = { high: 3, medium: 2, low: 1 };
  const minLevel = confidenceLevels[minConfidence];

  return ALL_SECRET_PATTERNS.some(({ pattern, confidence }) => {
    const level = confidenceLevels[confidence];
    return level >= minLevel && pattern.test(value);
  });
}

export function isSecretKey(
  key: string,
  minConfidence: 'high' | 'medium' | 'low' = 'low'
): boolean {
  const confidenceLevels = { high: 3, medium: 2, low: 1 };
  const minLevel = confidenceLevels[minConfidence];

  return SECRET_KEY_PATTERNS.some(({ pattern, confidence }) => {
    const level = confidenceLevels[confidence];
    return level >= minLevel && pattern.test(key);
  });
}

export function isPlaceholder(value: string): boolean {
  return PLACEHOLDER_PATTERNS.some((pattern) => pattern.test(value));
}
