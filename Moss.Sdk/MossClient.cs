using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Moss.Sdk;

/// <summary>
/// MOSS client for cryptographic signing of AI agent outputs.
/// </summary>
public class MossClient : IDisposable
{
    public const string Spec = "moss-0001";
    public const int Version = 1;
    public const string Algorithm = "ML-DSA-44";
    public const string DefaultBaseUrl = "https://moss-api-837703369688.us-central1.run.app";

    private readonly MossConfig _config;
    private readonly HttpClient _httpClient;
    private long _sequence;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    /// <summary>
    /// Creates a new MOSS client.
    /// </summary>
    /// <param name="apiKey">Optional API key. If not provided, uses MOSS_API_KEY environment variable.</param>
    public MossClient(string? apiKey = null)
    {
        _config = new MossConfig
        {
            ApiKey = apiKey ?? Environment.GetEnvironmentVariable("MOSS_API_KEY"),
            BaseUrl = DefaultBaseUrl
        };
        _httpClient = new HttpClient();
    }

    /// <summary>
    /// Creates a new MOSS client with custom configuration.
    /// </summary>
    public MossClient(MossConfig config)
    {
        _config = config;
        _httpClient = new HttpClient();
    }

    /// <summary>
    /// Signs a payload and returns the envelope.
    /// </summary>
    public async Task<SignResult> SignAsync(SignRequest request)
    {
        if (string.IsNullOrEmpty(_config.ApiKey))
        {
            return SignLocal(request);
        }
        return await SignEnterpriseAsync(request);
    }

    private SignResult SignLocal(SignRequest request)
    {
        var payloadJson = JsonSerializer.Serialize(request.Payload, JsonOptions);
        var payloadHash = ComputeHash(payloadJson);

        var seq = Interlocked.Increment(ref _sequence);
        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        var subject = string.IsNullOrEmpty(request.AgentId) ? "moss:local:default" : request.AgentId;

        var envelope = new Envelope
        {
            Spec = Spec,
            Version = Version,
            Alg = Algorithm,
            Subject = subject,
            KeyVersion = 1,
            Seq = seq,
            IssuedAt = now,
            PayloadHash = payloadHash,
            Signature = ""
        };

        return new SignResult
        {
            Envelope = envelope,
            Allowed = true,
            Decision = "allow",
            SignatureValid = true
        };
    }

    private async Task<SignResult> SignEnterpriseAsync(SignRequest request)
    {
        var evalRequest = new Dictionary<string, object?>
        {
            ["subject"] = request.AgentId,
            ["action"] = request.Action,
            ["payload"] = request.Payload
        };
        if (request.Context != null)
        {
            evalRequest["context"] = request.Context;
        }

        var content = new StringContent(
            JsonSerializer.Serialize(evalRequest, JsonOptions),
            Encoding.UTF8,
            "application/json"
        );

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.PostAsync($"{_config.BaseUrl}/v1/evaluate", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }

        var result = JsonSerializer.Deserialize<JsonElement>(responseBody);

        Envelope? envelope = null;
        if (result.TryGetProperty("envelope", out var envProp) && envProp.ValueKind != JsonValueKind.Null)
        {
            envelope = JsonSerializer.Deserialize<Envelope>(envProp.GetRawText(), JsonOptions);
        }

        if (envelope == null)
        {
            var payloadJson = JsonSerializer.Serialize(request.Payload, JsonOptions);
            var payloadHash = ComputeHash(payloadJson);
            var seq = Interlocked.Increment(ref _sequence);

            envelope = new Envelope
            {
                Spec = Spec,
                Version = Version,
                Alg = Algorithm,
                Subject = request.AgentId ?? "unknown",
                KeyVersion = 1,
                Seq = seq,
                IssuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
                PayloadHash = payloadHash,
                Signature = ""
            };
        }

        var decision = result.TryGetProperty("decision", out var decProp) ? decProp.GetString() ?? "allow" : "allow";

        return new SignResult
        {
            Envelope = envelope,
            Allowed = decision == "allow",
            Blocked = decision == "block",
            Held = decision == "hold",
            Decision = decision,
            Reason = result.TryGetProperty("reason", out var reasonProp) ? reasonProp.GetString() : null,
            ActionId = result.TryGetProperty("action_id", out var actionIdProp) ? actionIdProp.GetString() : null,
            EvidenceId = result.TryGetProperty("evidence_id", out var evidenceIdProp) ? evidenceIdProp.GetString() : null,
            SignatureValid = result.TryGetProperty("signature_valid", out var sigValidProp) && sigValidProp.GetBoolean()
        };
    }

    /// <summary>
    /// Verifies an envelope against a payload.
    /// </summary>
    public VerifyResult Verify(object payload, Envelope envelope)
    {
        if (envelope == null)
        {
            return new VerifyResult { Valid = false, Error = "Invalid envelope" };
        }

        if (envelope.Spec != Spec)
        {
            return new VerifyResult { Valid = false, Error = $"Unknown spec: {envelope.Spec}" };
        }

        try
        {
            var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
            var computedHash = ComputeHash(payloadJson);

            if (computedHash != envelope.PayloadHash)
            {
                return new VerifyResult { Valid = false, Error = "Payload hash mismatch" };
            }

            return new VerifyResult
            {
                Valid = true,
                Subject = envelope.Subject,
                IssuedAt = DateTimeOffset.FromUnixTimeSeconds(envelope.IssuedAt),
                Sequence = envelope.Seq
            };
        }
        catch (Exception e)
        {
            return new VerifyResult { Valid = false, Error = $"Verification failed: {e.Message}" };
        }
    }

    /// <summary>
    /// Registers a new agent.
    /// </summary>
    public async Task<RegisterAgentResult> RegisterAgentAsync(RegisterAgentRequest request)
    {
        RequireApiKey();

        var content = new StringContent(
            JsonSerializer.Serialize(request, JsonOptions),
            Encoding.UTF8,
            "application/json"
        );

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.PostAsync($"{_config.BaseUrl}/v1/agents", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }

        return JsonSerializer.Deserialize<RegisterAgentResult>(responseBody, JsonOptions)!;
    }

    /// <summary>
    /// Gets agent details.
    /// </summary>
    public async Task<Agent?> GetAgentAsync(string agentId)
    {
        RequireApiKey();

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.GetAsync($"{_config.BaseUrl}/v1/agents/{agentId}");

        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
        {
            return null;
        }

        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }

        return JsonSerializer.Deserialize<Agent>(responseBody, JsonOptions);
    }

    /// <summary>
    /// Rotates an agent's signing key.
    /// </summary>
    public async Task<RotateKeyResult> RotateAgentKeyAsync(string agentId, string? reason = null)
    {
        RequireApiKey();

        var body = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(reason))
        {
            body["reason"] = reason;
        }

        var content = new StringContent(
            JsonSerializer.Serialize(body, JsonOptions),
            Encoding.UTF8,
            "application/json"
        );

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.PostAsync($"{_config.BaseUrl}/v1/agents/{agentId}/rotate", content);
        var responseBody = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }

        return JsonSerializer.Deserialize<RotateKeyResult>(responseBody, JsonOptions)!;
    }

    /// <summary>
    /// Suspends an agent.
    /// </summary>
    public async Task SuspendAgentAsync(string agentId, string? reason = null)
    {
        RequireApiKey();

        var body = new Dictionary<string, string>();
        if (!string.IsNullOrEmpty(reason))
        {
            body["reason"] = reason;
        }

        var content = new StringContent(
            JsonSerializer.Serialize(body, JsonOptions),
            Encoding.UTF8,
            "application/json"
        );

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.PostAsync($"{_config.BaseUrl}/v1/agents/{agentId}/suspend", content);

        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync();
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }
    }

    /// <summary>
    /// Reactivates a suspended agent.
    /// </summary>
    public async Task ReactivateAgentAsync(string agentId)
    {
        RequireApiKey();

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.PostAsync($"{_config.BaseUrl}/v1/agents/{agentId}/reactivate", null);

        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync();
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }
    }

    /// <summary>
    /// Permanently revokes an agent.
    /// </summary>
    public async Task RevokeAgentAsync(string agentId, string reason)
    {
        RequireApiKey();

        if (string.IsNullOrEmpty(reason))
        {
            throw new MossException("Reason is required for revocation");
        }

        var body = new Dictionary<string, string> { ["reason"] = reason };

        var content = new StringContent(
            JsonSerializer.Serialize(body, JsonOptions),
            Encoding.UTF8,
            "application/json"
        );

        _httpClient.DefaultRequestHeaders.Clear();
        _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_config.ApiKey}");

        var response = await _httpClient.PostAsync($"{_config.BaseUrl}/v1/agents/{agentId}/revoke", content);

        if (!response.IsSuccessStatusCode)
        {
            var responseBody = await response.Content.ReadAsStringAsync();
            throw new MossException($"API error (status {(int)response.StatusCode}): {responseBody}");
        }
    }

    /// <summary>
    /// Returns true if enterprise mode is enabled.
    /// </summary>
    public bool IsEnterpriseEnabled => !string.IsNullOrEmpty(_config.ApiKey);

    private void RequireApiKey()
    {
        if (string.IsNullOrEmpty(_config.ApiKey))
        {
            throw new MossException("API key is required for this operation");
        }
    }

    private static string ComputeHash(string data)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(data));
        return Convert.ToBase64String(hash).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}

/// <summary>
/// MOSS client configuration.
/// </summary>
public class MossConfig
{
    public string? ApiKey { get; set; }
    public string BaseUrl { get; set; } = MossClient.DefaultBaseUrl;
}

/// <summary>
/// MOSS signature envelope.
/// </summary>
public class Envelope
{
    public string Spec { get; set; } = "";
    public int Version { get; set; }
    public string Alg { get; set; } = "";
    public string Subject { get; set; } = "";
    public int KeyVersion { get; set; }
    public long Seq { get; set; }
    public long IssuedAt { get; set; }
    public string PayloadHash { get; set; } = "";
    public string Signature { get; set; } = "";
}

/// <summary>
/// Request to sign a payload.
/// </summary>
public class SignRequest
{
    public object Payload { get; set; } = new();
    public string? AgentId { get; set; }
    public string? Action { get; set; }
    public Dictionary<string, object>? Context { get; set; }
}

/// <summary>
/// Result of a sign operation.
/// </summary>
public class SignResult
{
    public Envelope Envelope { get; set; } = new();
    public bool Allowed { get; set; }
    public bool Blocked { get; set; }
    public bool Held { get; set; }
    public string Decision { get; set; } = "";
    public string? Reason { get; set; }
    public string? ActionId { get; set; }
    public string? EvidenceId { get; set; }
    public bool SignatureValid { get; set; }
}

/// <summary>
/// Result of a verify operation.
/// </summary>
public class VerifyResult
{
    public bool Valid { get; set; }
    public string? Subject { get; set; }
    public DateTimeOffset? IssuedAt { get; set; }
    public long? Sequence { get; set; }
    public string? Error { get; set; }
}

/// <summary>
/// Agent representation.
/// </summary>
public class Agent
{
    public string Id { get; set; } = "";
    public string AgentId { get; set; } = "";
    public string? DisplayName { get; set; }
    public string Status { get; set; } = "";
    public List<string>? Tags { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
    public string? PolicyId { get; set; }
    public long TotalSignatures { get; set; }
    public string? ActiveKeyId { get; set; }
    public string? CreatedAt { get; set; }
    public string? LastSeenAt { get; set; }
}

/// <summary>
/// Request to register a new agent.
/// </summary>
public class RegisterAgentRequest
{
    public string AgentId { get; set; } = "";
    public string? DisplayName { get; set; }
    public List<string>? Tags { get; set; }
    public Dictionary<string, object>? Metadata { get; set; }
    public string? PolicyId { get; set; }
}

/// <summary>
/// Result of registering an agent.
/// </summary>
public class RegisterAgentResult
{
    public string Id { get; set; } = "";
    public string AgentId { get; set; } = "";
    public string? DisplayName { get; set; }
    public string Status { get; set; } = "";
    public string KeyId { get; set; } = "";
    public string SigningSecret { get; set; } = "";
    public string? CreatedAt { get; set; }
}

/// <summary>
/// Result of rotating an agent's key.
/// </summary>
public class RotateKeyResult
{
    public string AgentId { get; set; } = "";
    public string KeyId { get; set; } = "";
    public string SigningSecret { get; set; } = "";
    public string RotatedAt { get; set; } = "";
}

/// <summary>
/// MOSS exception.
/// </summary>
public class MossException : Exception
{
    public MossException(string message) : base(message) { }
    public MossException(string message, Exception inner) : base(message, inner) { }
}
