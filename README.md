# MOSS .NET SDK

**Unsigned agent output is broken output.**

MOSS (Message-Origin Signing System) provides cryptographic signing for AI agents. Every output is signed with ML-DSA-44 (post-quantum), creating non-repudiable execution records with audit-grade provenance.

## Install

```bash
dotnet add package Moss.Sdk
```

## Quick Start

```csharp
using Moss.Sdk;

// Create client (uses MOSS_API_KEY env var if set)
using var client = new MossClient(Environment.GetEnvironmentVariable("MOSS_API_KEY"));

// Sign any agent output
var result = await client.SignAsync(new SignRequest
{
    Payload = new { action = "transfer", amount = 500 },
    AgentId = "agent-finance-01"
});

Console.WriteLine($"Signed! Hash: {result.Envelope.PayloadHash}");
Console.WriteLine($"Decision: {result.Decision}");

// Verify offline
var verifyResult = client.Verify(
    new { action = "transfer", amount = 500 },
    result.Envelope
);

if (verifyResult.Valid)
{
    Console.WriteLine($"Verified! Signed by: {verifyResult.Subject}");
}
```

## Enterprise Features

With an API key, you get policy evaluation, approval workflows, and audit logging:

```csharp
using var client = new MossClient(Environment.GetEnvironmentVariable("MOSS_API_KEY"));

var result = await client.SignAsync(new SignRequest
{
    Payload = new 
    { 
        action = "high_risk_transfer",
        amount = 1000000,
        recipient = "external-account"
    },
    AgentId = "finance-bot",
    Action = "transfer",
    Context = new Dictionary<string, object>
    {
        ["user_id"] = "u123",
        ["department"] = "finance"
    }
});

switch (result.Decision)
{
    case "allow":
        Console.WriteLine("Action allowed");
        break;
    case "block":
        Console.WriteLine($"Action blocked: {result.Reason}");
        break;
    case "hold":
        Console.WriteLine($"Action held for approval: {result.ActionId}");
        break;
}
```

## Agent Lifecycle Management

```csharp
// Register a new agent
var agent = await client.RegisterAgentAsync(new RegisterAgentRequest
{
    AgentId = "my-new-agent",
    DisplayName = "My New Agent",
    Tags = new List<string> { "production", "finance" }
});
Console.WriteLine($"Signing secret (save this!): {agent.SigningSecret}");

// Get agent details
var existing = await client.GetAgentAsync("my-new-agent");
if (existing != null)
{
    Console.WriteLine($"Status: {existing.Status}, Signatures: {existing.TotalSignatures}");
}

// Rotate key (returns new signing secret)
var rotateResult = await client.RotateAgentKeyAsync("my-new-agent", "quarterly rotation");
Console.WriteLine($"New signing secret: {rotateResult.SigningSecret}");

// Suspend agent (can be reactivated)
await client.SuspendAgentAsync("my-new-agent", "suspicious activity");

// Reactivate agent
await client.ReactivateAgentAsync("my-new-agent");

// Permanently revoke agent
await client.RevokeAgentAsync("my-new-agent", "compromised credentials");
```

## Envelope Format

Every signed action produces a verifiable envelope:

```csharp
var envelope = result.Envelope;
Console.WriteLine($"Spec: {envelope.Spec}");           // "moss-0001"
Console.WriteLine($"Version: {envelope.Version}");     // 1
Console.WriteLine($"Algorithm: {envelope.Alg}");       // "ML-DSA-44"
Console.WriteLine($"Subject: {envelope.Subject}");     // Agent ID
Console.WriteLine($"Key Version: {envelope.KeyVersion}");
Console.WriteLine($"Sequence: {envelope.Seq}");
Console.WriteLine($"Issued At: {envelope.IssuedAt}");
Console.WriteLine($"Payload Hash: {envelope.PayloadHash}");
```

## Configuration

```csharp
using var client = new MossClient(new MossConfig
{
    ApiKey = "your_api_key",
    BaseUrl = "https://moss-api.example.com"
});
```

## Error Handling

```csharp
try
{
    var result = await client.SignAsync(request);
}
catch (MossException e)
{
    Console.WriteLine($"MOSS error: {e.Message}");
}
```

## Pricing Tiers

| Tier | Price | Agents | Signatures | Retention |
|------|-------|--------|------------|-----------|
| **Free** | $0 | 5 | 1,000/day | 7 days |
| **Pro** | $1,499/mo | Unlimited | Unlimited | 1 year |
| **Enterprise** | Custom | Unlimited | Unlimited | 7 years |

*Annual billing: $1,249/mo (save $3,000/year)*

All new signups get a **14-day free trial** of Pro.

## Requirements

- .NET 8.0 or higher

## Links

- [mosscomputing.com](https://mosscomputing.com) — Project site
- [app.mosscomputing.com](https://app.mosscomputing.com) — Dashboard
- [Python SDK](https://github.com/mosscomputing/moss) — moss-sdk
- [Go SDK](https://github.com/mosscomputing/moss-go) — moss-go

## License

Proprietary - See LICENSE for terms.

Copyright (c) 2025-2026 IAMPASS Inc. All Rights Reserved.
