# API Security Shield 🛡️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.5+-blue.svg)](https://www.typescriptlang.org/)
[![pnpm](https://img.shields.io/badge/maintained%20with-pnpm-cc00ff.svg)](https://pnpm.io/)

**Intelligent, Event-Driven API Protection for Modern Node.js Applications.**

API Security Shield is a high-performance, extensible security middleware designed to protect your APIs from automated threats, brute force attacks, and malicious traffic. Built with a plugin-first architecture, it provides real-time detection and response capabilities.

## ✨ Features

- 🕵️ **Advanced Bot Detection**: Multi-layered analysis including User-Agent, behavioral frequency, and fingerprint correlation.
- ⚡ **Adaptive Rate Limiting**: Intelligent throttling that scales based on threat scores and reputation.
- 🛡️ **Threat Detection Engine**: Built-in detectors for SQLi, XSS, and common attack patterns.
- 🔌 **Dynamic Plugin System**: Extend the shield with custom detectors, analyzers, and actions using the provided SDK.
- 🪝 **Real-time Webhooks**: Get instant notifications via Discord, Slack, or generic HTTP webhooks.
- 📊 **Security Dashboard API**: Real-time metrics and event logging for monitoring your API's security health.
- 💾 **Multi-Storage Support**: High-performance Memory and Redis adapters for distributed deployments.

## 🚀 Getting Started

### Installation

```bash
pnpm add @api-security-shield/core
```

### Basic Usage (Express)

```typescript
import express from 'express';
import { SecurityShield } from '@api-security-shield/core';

const app = express();
const shield = new SecurityShield({
  rateLimit: { windowMs: 60000, max: 100 },
  botDetection: { enabled: true }
});

app.use(shield.middleware());

app.get('/api/data', (req, res) => {
  res.json({ message: "Secure Data" });
});

app.listen(3000);
```

## 🛠️ Advanced Features

### Plugin System
Create custom security logic easily:

```typescript
class MyCustomPlugin extends SecurityPlugin {
  metadata = { name: "custom-logger", version: "1.0.0" };
  async onEvent(event) {
    if (event.type === 'threat.detected') {
      console.warn(`Critical threat: ${event.data.reason}`);
    }
  }
}

shield.plugins.load(new MyCustomPlugin());
```

### Real-time Webhooks
Register notification providers:

```typescript
shield.webhooks.register({
  eventTypes: ["bot.detected", "threat.detected"],
  provider: new DiscordWebhookProvider({ url: process.env.DISCORD_URL })
});
```

## 📚 Documentation

- [Architecture](docs/ARCHITECTURE.md) - Deep dive into the event-driven core.
- [Plugin Development](packages/plugins/README.md) - Learn how to build your own extensions.
- [API Reference](docs/API_REFERENCE.md) - Complete documentation of all modules.
- [Security Dashboard](packages/dashboard/README.md) - How to consume security metrics.

## 🛡️ Security

If you discover a security vulnerability, please see our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
