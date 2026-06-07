# API Security Shield - Core 🛡️

[![npm version](https://img.shields.io/npm/v/api-security-shield-core.svg)](https://www.npmjs.com/package/api-security-shield-core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20.11+-green.svg)](https://nodejs.org/)

**Core security engine for intelligent API protection in Node.js applications.**

The core module of API Security Shield provides the foundation for protecting your APIs from automated threats, brute force attacks, and malicious traffic. Built with TypeScript and a plugin-first architecture, it enables real-time threat detection and adaptive responses.

## 📦 What's Included

- **Threat Detection Engine**: Multi-layered detection for SQL injection, XSS, and common attack patterns
- **Adaptive Rate Limiting**: Intelligent request throttling based on threat assessment
- **Bot Detection**: Advanced fingerprinting and behavioral analysis
- **Event System**: Real-time event bus for security events
- **Extensible Architecture**: Plugin system for custom detectors and analyzers
- **Storage Adapters**: Memory and Redis support for distributed deployments
- **Middleware Integration**: Express, Fastify, and NestJS compatible

## 🚀 Quick Start

### Installation

```bash
npm install api-security-shield
# or
pnpm add api-security-shield
# or
yarn add api-security-shield
```

### Basic Usage

```typescript
import { SecurityShield } from 'api-security-shield-core';
import express from 'express';

const app = express();
const shield = new SecurityShield({
  rateLimit: {
    windowMs: 60000,      // 1 minute
    max: 100              // 100 requests per window
  },
  botDetection: {
    enabled: true,
    sensitivity: 'high'   // low | medium | high
  }
});

// Apply middleware
app.use(shield.middleware());

app.get('/api/data', (req, res) => {
  res.json({ message: 'Protected endpoint' });
});

app.listen(3000, () => {
  console.log('Server running on port 3000 with Shield protection');
});
```

## 🔧 Configuration

### Core Options

```typescript
interface ShieldConfig {
  // Rate limiting
  rateLimit?: {
    windowMs: number;      // Time window in ms
    max: number;           // Max requests per window
    message?: string;      // Custom rate limit message
  };

  // Bot detection
  botDetection?: {
    enabled: boolean;
    sensitivity: 'low' | 'medium' | 'high';
    threshold?: number;    // 0-100 score threshold
  };

  // Threat detection
  threatDetection?: {
    sqlInjection: boolean;
    xss: boolean;
    customPatterns?: RegExp[];
  };

  // Storage adapter (memory or redis)
  storage?: StorageAdapter;

  // Event handlers
  onThreat?: (event: ThreatEvent) => void;
  onRateLimit?: (event: RateLimitEvent) => void;
}
```

## 📊 Event System

Listen to security events in real-time:

```typescript
shield.on('threat', (event) => {
  console.log(`Threat detected: ${event.type}`, {
    source: event.ip,
    severity: event.severity,
    timestamp: event.timestamp
  });
});

shield.on('rate-limit', (event) => {
  console.log(`Rate limit exceeded for ${event.ip}`);
});

shield.on('bot', (event) => {
  console.log(`Bot detected with score: ${event.score}`);
});
```

## 🔌 Storage Adapters

### Memory Adapter (Default)

```typescript
import { MemoryStorageAdapter } from 'api-security-shield-core';

const shield = new SecurityShield({
  storage: new MemoryStorageAdapter()
});
```

### Redis Adapter

```typescript
import { RedisStorageAdapter } from '@api-security-shield/redis';
import Redis from 'ioredis';

const redis = new Redis({
  host: 'localhost',
  port: 6379
});

const shield = new SecurityShield({
  storage: new RedisStorageAdapter(redis)
});
```

## 🎯 Advanced Features

### Custom Threat Detectors

```typescript
import { CustomDetector } from 'api-security-shield-core';

class MyCustomDetector extends CustomDetector {
  detect(request) {
    // Your detection logic
    return {
      detected: false,
      score: 0,
      message: 'Custom check passed'
    };
  }
}

shield.registerDetector(new MyCustomDetector());
```

### Threat Scoring

The shield assigns threat scores (0-100) based on multiple factors:

| Score Range | Level | Action |
|------------|-------|--------|
| 0-20 | Low | Allow request |
| 21-50 | Medium | Monitor & log |
| 51-80 | High | Rate limit |
| 81-100 | Critical | Block immediately |

### Request Context

Access security context in your handlers:

```typescript
app.get('/api/data', (req: any, res) => {
  const shieldContext = req.shieldContext;
  
  console.log({
    threatScore: shieldContext.threatScore,
    isBot: shieldContext.isBot,
    fingerprint: shieldContext.fingerprint,
    violations: shieldContext.violations
  });

  res.json({ data: 'sensitive' });
});
```

## 🔐 Security Best Practices

1. **Always validate input** - Shield complements but doesn't replace input validation
2. **Use HTTPS** - Always run in production with TLS/SSL
3. **Monitor events** - Set up alerts for high threat scores
4. **Update regularly** - Keep Shield and dependencies updated
5. **Test configuration** - Thoroughly test rate limits and detection rules
6. **Use Redis for distributed** - In production with multiple servers, use Redis adapter

## 📚 Middleware Integration

### Express

```typescript
import express from 'express';
import { SecurityShield } from 'api-security-shield-core';

const app = express();
const shield = new SecurityShield(config);
app.use(shield.middleware());
```

### Fastify

Install the Fastify adapter:
```bash
npm install @api-security-shield/fastify
```

```typescript
import Fastify from 'fastify';
import { fastifyShield } from '@api-security-shield/fastify';

const fastify = Fastify();
await fastify.register(fastifyShield, config);
```

### NestJS

Install the NestJS adapter:
```bash
npm install @api-security-shield/nestjs
```

```typescript
import { Module } from '@nestjs/common';
import { ShieldModule } from '@api-security-shield/nestjs';

@Module({
  imports: [ShieldModule.forRoot(config)]
})
export class AppModule {}
```

## 🚨 Error Handling

```typescript
shield.on('error', (error) => {
  console.error('Shield error:', error);
  // Handle errors gracefully
});

// Custom error responses
app.use((err: any, req: any, res: any, next: any) => {
  if (err.code === 'RATE_LIMIT_EXCEEDED') {
    return res.status(429).json({
      error: 'Too many requests',
      retryAfter: err.retryAfter
    });
  }

  if (err.code === 'THREAT_DETECTED') {
    return res.status(403).json({
      error: 'Request blocked',
      reason: err.reason
    });
  }

  next(err);
});
```

## 📊 Monitoring & Metrics

Access real-time metrics:

```typescript
const metrics = shield.getMetrics();

console.log({
  totalRequests: metrics.totalRequests,
  blockedRequests: metrics.blockedRequests,
  threatsDetected: metrics.threatsDetected,
  averageThreatScore: metrics.averageThreatScore,
  botsDetected: metrics.botsDetected
});
```

## 🔗 Webhook Integration

Send security events to external services:

```bash
npm install @api-security-shield/webhook
```

```typescript
import { WebhookAdapter } from '@api-security-shield/webhook';

const webhook = new WebhookAdapter({
  url: 'https://your-service.com/security-events',
  events: ['threat', 'bot', 'rate-limit'],
  retries: 3
});

shield.registerAdapter(webhook);
```

## 🧪 Testing

```typescript
import { createTestShield } from 'api-security-shield-core';

const shield = createTestShield({
  rateLimit: { windowMs: 1000, max: 5 }
});

// Simulate requests
const result = await shield.check({
  ip: '192.168.1.1',
  path: '/api/test',
  method: 'POST'
});

expect(result.threatScore).toBeLessThan(50);
```

## 🐛 Debugging

Enable debug mode to see detailed logs:

```typescript
const shield = new SecurityShield(config, {
  debug: true,
  logLevel: 'verbose'
});

// Or use environment variable
// DEBUG=api-security-shield:* node app.js
```

## 📖 Documentation

- [Full API Reference](https://github.com/akramhossain-dev/API-Security-Shield/blob/main/docs/API_REFERENCE.md)
- [Architecture Guide](https://github.com/akramhossain-dev/API-Security-Shield/blob/main/docs/ARCHITECTURE.md)
- [Plugin Development](https://github.com/akramhossain-dev/API-Security-Shield/blob/main/docs/CONTRIBUTING.md)
- [Examples](https://github.com/akramhossain-dev/API-Security-Shield/tree/main/examples)

## 🔗 Related Packages

- [@api-security-shield/express](https://www.npmjs.com/package/@api-security-shield/express) - Express integration
- [@api-security-shield/fastify](https://www.npmjs.com/package/@api-security-shield/fastify) - Fastify integration
- [@api-security-shield/redis](https://www.npmjs.com/package/@api-security-shield/redis) - Redis adapter
- [@api-security-shield/webhook](https://www.npmjs.com/package/@api-security-shield/webhook) - Webhook notifications

## 📜 License

MIT © 2024 [Akram Hossain](https://github.com/akramhossain-dev)

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](https://github.com/akramhossain-dev/API-Security-Shield/blob/main/docs/CONTRIBUTING.md) for guidelines.

## 🐛 Report Issues

Found a bug? Please report it on [GitHub Issues](https://github.com/akramhossain-dev/API-Security-Shield/issues)

## 📞 Support

- GitHub Discussions: [Discussion Board](https://github.com/akramhossain-dev/API-Security-Shield/discussions)
- Email: md.akramhossainjisan@gmail.com

---

**Made with ❤️ by the API Security Shield team**
