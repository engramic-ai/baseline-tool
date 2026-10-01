using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;

namespace Engramic.Baseline.Windows.Tests;

/// <summary>
/// Serves a PAC file at /wpad.dat on port 80 for the WPAD host names given, through http.sys, and records each
/// request as host and path.
/// </summary>
/// <remarks>
/// WPAD always fetches over port 80, and a machine may already use it: on CI's runner a socket of our own on it
/// is refused (WSAEACCES), as it is when http.sys has the port. http.sys shares the port between the names
/// registered with it, so registering only the WPAD names works alongside other users of port 80 through
/// http.sys, and leaves them alone. A failure to start names what is listening on port 80.
/// Registering needs an administrator or SYSTEM, as these tests are.
/// </remarks>
internal sealed class WpadServer : IDisposable
{
    private readonly HttpListener _listener = new();
    private readonly ConcurrentQueue<string> _requests = new();
    private readonly byte[] _script;
    private readonly Task _serving;

    /// <summary>Starts serving.</summary>
    /// <param name="names">The host names WPAD may ask for, such as wpad.example.test.</param>
    /// <param name="script">The PAC file's script.</param>
    public WpadServer(IEnumerable<string> names, string script)
    {
        _script = Encoding.ASCII.GetBytes(script);
        foreach (var name in names)
        {
            _listener.Prefixes.Add($"http://{name}:80/");
        }

        try
        {
            _listener.Start();
        }
        catch (HttpListenerException e)
        {
            var listening = IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Where(l => l.Port == 80).Select(l => l.ToString());
            throw new InvalidOperationException($"Could not serve wpad.dat on port 80 through http.sys ({e.Message}). Listening on port 80: {string.Join(", ", listening)}.", e);
        }

        _serving = Task.Run(ServeAsync);
    }

    /// <summary>Gets the requests received so far, as host and path, in order.</summary>
    public IReadOnlyList<string> Requests => [.. _requests];

    /// <summary>Stops serving.</summary>
    public void Dispose()
    {
        _listener.Close();
        try
        {
            _serving.Wait(TimeSpan.FromSeconds(5));
        }
        catch (AggregateException)
        {
            // The serving loop ends with the listener.
        }
    }

    private async Task ServeAsync()
    {
        while (_listener.IsListening)
        {
            HttpListenerContext context;
            try
            {
                context = await _listener.GetContextAsync();
            }
            catch (Exception e) when (e is HttpListenerException or ObjectDisposedException or InvalidOperationException)
            {
                return;
            }

            _requests.Enqueue($"{context.Request.UserHostName}{context.Request.RawUrl}");
            var response = context.Response;
            try
            {
                if (context.Request.Url?.AbsolutePath == "/wpad.dat")
                {
                    response.ContentType = "application/x-ns-proxy-autoconfig";
                    response.ContentLength64 = _script.Length;
                    await response.OutputStream.WriteAsync(_script);
                }
                else
                {
                    response.StatusCode = 404;
                }
            }
            catch (HttpListenerException)
            {
                // The client went away; WPAD asks again if it needs to.
            }
            finally
            {
                response.Close();
            }
        }
    }
}
