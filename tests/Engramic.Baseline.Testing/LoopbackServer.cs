using System.Collections.Concurrent;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Engramic.Baseline.Testing;

/// <summary>
/// A small HTTP/1.1 server on the loopback address, for tests of code that sends requests. It records the head
/// of every request and answers as the test says: as a site, as a proxy that answers CONNECT, or with a PAC file.
/// Connections are kept open between requests, as a proxy asking for NTLM needs.
/// </summary>
/// <remarks>Nothing leaves the device: it listens on 127.0.0.1 only, on a port the system picks unless one is given.</remarks>
public sealed class LoopbackServer : IDisposable
{
    private const int MaxHead = 64 * 1024;

    private readonly TcpListener _listener;
    private readonly Func<LoopbackRequest, LoopbackReply> _answer;
    private readonly ConcurrentQueue<LoopbackRequest> _requests = new();
    private readonly ConcurrentDictionary<TcpClient, bool> _clients = new();
    private readonly CancellationTokenSource _stop = new();
    private readonly Task _accepting;

    /// <summary>Starts the server.</summary>
    /// <param name="answer">How to answer each request.</param>
    /// <param name="port">The port to listen on; 0 for one the system picks.</param>
    public LoopbackServer(Func<LoopbackRequest, LoopbackReply> answer, int port = 0)
    {
        ArgumentNullException.ThrowIfNull(answer);
        _answer = answer;
        _listener = new TcpListener(IPAddress.Loopback, port);
        _listener.Start();
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
        _accepting = Task.Run(AcceptAsync);
    }

    /// <summary>Gets the port it listens on.</summary>
    public int Port { get; }

    /// <summary>Gets its address, http://127.0.0.1:port/.</summary>
    public Uri Address => new UriBuilder("http", "127.0.0.1", Port).Uri;

    /// <summary>Gets the requests received so far, in order.</summary>
    public IReadOnlyList<LoopbackRequest> Requests => [.. _requests];

    /// <summary>Gets the address of a path on it, such as /proxy.pac.</summary>
    /// <param name="path">The path.</param>
    /// <returns>The address.</returns>
    public Uri At(string path) => new(Address, path);

    /// <summary>Stops listening and closes every connection.</summary>
    public void Dispose()
    {
        _stop.Cancel();
        _listener.Stop();
        foreach (var client in _clients.Keys)
        {
            client.Dispose();
        }

        try
        {
            _accepting.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // The accept loop ends with the listener.
        }

        _stop.Dispose();
    }

    private async Task AcceptAsync()
    {
        while (!_stop.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(_stop.Token);
            }
            catch (Exception e) when (e is OperationCanceledException or ObjectDisposedException or SocketException)
            {
                return;
            }

            _clients[client] = true;
            _ = Task.Run(() => ServeAsync(client));
        }
    }

    private async Task ServeAsync(TcpClient client)
    {
        try
        {
            using (client)
            {
                var stream = client.GetStream();
                var buffered = new List<byte>();
                var chunk = new byte[4096];
                while (!_stop.IsCancellationRequested)
                {
                    int end;
                    while ((end = HeadEnd(buffered)) < 0)
                    {
                        var read = await stream.ReadAsync(chunk, _stop.Token);
                        if (read == 0 || buffered.Count > MaxHead)
                        {
                            return;
                        }

                        buffered.AddRange(chunk.AsSpan(0, read));
                    }

                    var request = LoopbackRequest.Parse(Encoding.ASCII.GetString(buffered.GetRange(0, end).ToArray()));
                    buffered.RemoveRange(0, end + 4);
                    _requests.Enqueue(request);
                    var reply = _answer(request);
                    if (reply.Hang)
                    {
                        await Task.Delay(Timeout.Infinite, _stop.Token);
                        return;
                    }

                    await stream.WriteAsync(reply.ToBytes(), _stop.Token);
                    if (reply.Close || string.Equals(request.Header("Connection"), "close", StringComparison.OrdinalIgnoreCase))
                    {
                        return;
                    }
                }
            }
        }
        catch (Exception e) when (e is OperationCanceledException or IOException or ObjectDisposedException or SocketException)
        {
            // The test ended, or the other end went away.
        }
        finally
        {
            _clients.TryRemove(client, out _);
        }
    }

    private static int HeadEnd(List<byte> bytes)
    {
        for (var i = 0; i + 3 < bytes.Count; i++)
        {
            if (bytes[i] == '\r' && bytes[i + 1] == '\n' && bytes[i + 2] == '\r' && bytes[i + 3] == '\n')
            {
                return i;
            }
        }

        return -1;
    }
}

/// <summary>The head of a request the loopback server received.</summary>
/// <param name="Method">The method, such as GET or CONNECT.</param>
/// <param name="Target">The request target: a path, or host:port for CONNECT.</param>
/// <param name="Headers">The headers, in order.</param>
public sealed record LoopbackRequest(string Method, string Target, IReadOnlyList<KeyValuePair<string, string>> Headers)
{
    /// <summary>Gets the value of a header, matched without regard to case, or null when there is none.</summary>
    /// <param name="name">The header's name.</param>
    /// <returns>The value of its first appearance.</returns>
    public string? Header(string name)
    {
        return Headers.Where(h => string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase)).Select(h => h.Value).FirstOrDefault();
    }

    internal static LoopbackRequest Parse(string head)
    {
        var lines = head.Split("\r\n");
        var start = lines[0].Split(' ');
        var headers = lines.Skip(1)
            .Select(l => l.Split(':', 2))
            .Where(p => p.Length == 2)
            .Select(p => new KeyValuePair<string, string>(p[0].Trim(), p[1].Trim()))
            .ToList();
        return new LoopbackRequest(start[0], start.Length > 1 ? start[1] : string.Empty, headers);
    }
}

/// <summary>How the loopback server answers a request.</summary>
public sealed record LoopbackReply
{
    /// <summary>Gets the status code.</summary>
    public int Status { get; init; } = 200;

    /// <summary>Gets the reason phrase.</summary>
    public string Reason { get; init; } = "OK";

    /// <summary>Gets the headers, besides Content-Length, which is added.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = [];

    /// <summary>Gets the body.</summary>
    public ReadOnlyMemory<byte> Body { get; init; }

    /// <summary>Gets whether to close the connection after answering.</summary>
    public bool Close { get; init; }

    /// <summary>Gets whether to answer nothing at all, holding the connection open until the server stops.</summary>
    public bool Hang { get; init; }

    /// <summary>A 200 answer with a body.</summary>
    /// <param name="body">The body, in UTF-8.</param>
    /// <param name="headers">Headers as name and value, one after the other.</param>
    /// <returns>The answer.</returns>
    public static LoopbackReply Ok(string body, params string[] headers) => With(200, "OK", body, headers);

    /// <summary>An answer with a status and no body.</summary>
    /// <param name="status">The status code.</param>
    /// <param name="reason">The reason phrase.</param>
    /// <param name="headers">Headers as name and value, one after the other.</param>
    /// <returns>The answer.</returns>
    public static LoopbackReply Of(int status, string reason, params string[] headers) => With(status, reason, string.Empty, headers);

    /// <summary>A PAC file with a script.</summary>
    /// <param name="script">The script, which defines FindProxyForURL.</param>
    /// <returns>The answer.</returns>
    public static LoopbackReply Pac(string script) => With(200, "OK", script, "Content-Type", "application/x-ns-proxy-autoconfig") with { Close = true };

    /// <summary>No answer at all.</summary>
    /// <returns>The answer.</returns>
    public static LoopbackReply Silence() => new() { Hang = true };

    internal byte[] ToBytes()
    {
        var head = new StringBuilder();
        head.Append(CultureInfo.InvariantCulture, $"HTTP/1.1 {Status} {Reason}\r\n");
        foreach (var header in Headers)
        {
            head.Append(CultureInfo.InvariantCulture, $"{header.Key}: {header.Value}\r\n");
        }

        head.Append(CultureInfo.InvariantCulture, $"Content-Length: {Body.Length}\r\n");
        if (Close)
        {
            head.Append("Connection: close\r\n");
        }

        head.Append("\r\n");
        return [.. Encoding.ASCII.GetBytes(head.ToString()), .. Body.Span];
    }

    private static LoopbackReply With(int status, string reason, string body, params string[] headers)
    {
        if (headers.Length % 2 != 0)
        {
            throw new ArgumentException("Give each header as a name and a value.", nameof(headers));
        }

        return new LoopbackReply
        {
            Status = status,
            Reason = reason,
            Body = Encoding.UTF8.GetBytes(body),
            Headers = [.. headers.Chunk(2).Select(h => new KeyValuePair<string, string>(h[0], h[1]))],
        };
    }
}
