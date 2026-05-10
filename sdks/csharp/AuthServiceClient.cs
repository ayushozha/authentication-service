using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace AuthService;

public sealed class AuthServiceClient
{
    private readonly HttpClient _http;
    private readonly string? _apiKey;
    private readonly string? _adminKey;
    public string? AccessToken { get; private set; }
    public string? RefreshToken { get; private set; }

    public AuthServiceClient(string baseUrl, string? apiKey = null, string? adminKey = null, HttpClient? http = null)
    {
        _http = http ?? new HttpClient();
        _http.BaseAddress = new Uri(baseUrl.TrimEnd('/') + "/");
        _apiKey = apiKey;
        _adminKey = adminKey;
    }

    public async Task<JsonDocument?> RequestAsync(string method, string path, object? body = null, bool admin = false, bool auth = true, CancellationToken ct = default)
    {
        using var request = new HttpRequestMessage(new HttpMethod(method), path.TrimStart('/'));
        if (body is not null) request.Content = new StringContent(JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
        if (admin && _adminKey is not null) request.Headers.Add("X-Admin-Key", _adminKey);
        else if (_apiKey is not null) request.Headers.Add("X-API-Key", _apiKey);
        if (auth && AccessToken is not null) request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", AccessToken);
        using var response = await _http.SendAsync(request, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode) throw new InvalidOperationException($"AuthService {(int)response.StatusCode}: {text}");
        return string.IsNullOrWhiteSpace(text) ? null : JsonDocument.Parse(text);
    }

    public async Task<JsonDocument?> LoginAsync(string email, string password, CancellationToken ct = default)
    {
        var doc = await RequestAsync("POST", "/api/auth/login", new { email, password, session_mode = "token" }, false, false, ct);
        if (doc is not null && doc.RootElement.TryGetProperty("access_token", out var access)) AccessToken = access.GetString();
        if (doc is not null && doc.RootElement.TryGetProperty("refresh_token", out var refresh)) RefreshToken = refresh.GetString();
        return doc;
    }

    public Task<JsonDocument?> MeAsync(CancellationToken ct = default) => RequestAsync("GET", "/api/auth/me", ct: ct);
    public Task<JsonDocument?> CreateClientAsync(object body, CancellationToken ct = default) => RequestAsync("POST", "/api/admin/clients", body, true, false, ct);
    public Task<JsonDocument?> CreateServiceAccountAsync(string clientId, object body, CancellationToken ct = default) => RequestAsync("POST", $"/api/admin/clients/{clientId}/service-accounts", body, true, false, ct);
}
