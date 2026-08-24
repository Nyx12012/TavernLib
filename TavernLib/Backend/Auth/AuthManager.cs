using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using TavernLib.Backend.Api;
using TavernLib.Backend.Server.Configs;

namespace TavernLib.Backend.Auth;

internal class AuthManager
{
    private TavernManager _manager;
    private TcpListener _listener;

    // Every read-modify-write of Users.json goes through this. Static because the
    // file is shared even if something ever constructs a second manager.
    private static readonly object UsersFileLock = new();

    // Same idea for whitelist_requests.json. Seperate lock, seperate files
    // So a whitelist application never blocks a join.
    private static readonly object WhitelistRequestsFileLock = new();

    private const ulong BaseUserID = 1000000000UL;

    public AuthManager(TavernManager manager)
    {
        _manager = manager;
        _listener = new(IPAddress.Any, 1762);

        _ = StartAuthCycle();
    }


    private async Task StartAuthCycle()
    {
        TavernLogger.Msg("Starting auth cycle");

        _listener.Start();

        var stopOnQuit = new CancellationTokenSource();
        UnityEngine.Application.quitting += stopOnQuit.Cancel;

        TavernLogger.Msg("Starting auth listening cycle");
        while (!stopOnQuit.IsCancellationRequested)
        {
            TcpClient client = await _listener.AcceptTcpClientAsync();
            _ = InterpretTcpStream(client);
        }
    }

    private async Task<string> ReadFullPayload(Stream stream, CancellationToken token)
    {
        TavernLogger.Msg("Reading payload");

        var buffer = new byte[4096];
        var totalRead = 0;

        while (totalRead < buffer.Length)
        {
            var bytesRead = await stream.ReadAsync(buffer, totalRead, buffer.Length - totalRead, token);
            if (bytesRead == 0) break;

            totalRead += bytesRead;
            var currentText = Encoding.UTF8.GetString(buffer, 0, totalRead).Trim();

            if (currentText.StartsWith("{") && currentText.EndsWith("}"))
            {
                try
                {
                    JObject.Parse(currentText);
                    return currentText;
                }
                catch (JsonReaderException)
                {
                }
            }
        }

        throw new Exception("Invalid or incomplete payload received.");
    }

    private async Task InterpretTcpStream(TcpClient client)
    {
        TavernLogger.Msg($"Connected to TcpClient ({(client.Client.RemoteEndPoint as IPEndPoint)?.Address}), interpreting stream");

        try
        {
            using var stream = client.GetStream();
            using var timeout = new CancellationTokenSource();
            timeout.CancelAfter(TimeSpan.FromSeconds(5));

            var payload = await ReadFullPayload(stream, timeout.Token);

            TavernLogger.Msg("Finding payload type");

            var jsonPayload = JObject.Parse(payload);

            if (jsonPayload.ContainsKey("ping")) await WritePongResponse(stream);
            else if (jsonPayload.ContainsKey("register_whitelist_application")) await ManageWhitelistApplicationRequest(stream, jsonPayload, client);
            else if (jsonPayload.ContainsKey("username")) await ManageAuthRequest(stream, jsonPayload, client);
            else
            {
                TavernLogger.Warn($"Unknown payload sent to AuthManager {jsonPayload}");
            }
        }
        catch (OperationCanceledException)
        {
            TavernLogger.Msg("Joining client sent no complete payload within the timeout");
        }
        catch (Exception e)
        {
            TavernLogger.Error($"Error decoding TCP stream {e}");
        }

        finally
        {
            TavernLogger.Msg("Closing connection to joining user");
            client.Close();
        }
    }
    private async Task WritePongResponse(Stream stream)
    {
        var response = new AuthPayloads.PingResponse(
            _manager.ServerConfig.LastRead.Name,
            !string.IsNullOrWhiteSpace(_manager.ServerConfig.LastRead.PasswordHash),
            _manager.UserConfig.LastRead.Whitelist.Usernames.Count > 0 || _manager.UserConfig.LastRead.Whitelist.Ips.Count > 0,
            1757); // TODO

        await WriteResponse(stream, response);
    }


    private async Task ManageAuthRequest(Stream stream, JObject payload, TcpClient joiner)
    {
        try
        {
            _manager.UserConfig.ReadFromFile(); // Read to make sure validation can be up-to date

            var typedPayload = JsonConvert.DeserializeObject<AuthPayloads.AuthenticateRequest>(payload.ToString());
            if (string.IsNullOrWhiteSpace(typedPayload.Token) || string.IsNullOrWhiteSpace(typedPayload.Username))
            {
                await WriteResponse(stream, new AuthPayloads.GenericFail("Malformed authentication data"));
                return;
            }


            var joinerIp = ((IPEndPoint)joiner.Client.RemoteEndPoint).Address.ToString();

            TavernLogger.Msg($"User at {joinerIp} joining server");
            TavernLogger.Msg($"With payload {payload}");

            if (!await CheckIfPermitted(joinerIp, typedPayload, stream)) return;

            await PostPermissionCheck(stream, typedPayload, joinerIp);
        }
        catch (Exception e)
        {
            TavernLogger.Error($"Error when managing join request {e}");
            throw;
        }
    }

private async Task PostPermissionCheck(Stream stream, AuthPayloads.AuthenticateRequest payload, string ip)
{
    await WriteResponse(stream, ResolveJoin(payload, ip));
}

// Read, decide, then write of Users.json happens under one lock, so two joiners
// landing at the same instant can't mint the same UserId or drop each other's
// entry. Deliberately has no awaits: the socket write happens after the lock is
// released, so a client that never reads can't stall everyone else's join.
private object ResolveJoin(AuthPayloads.AuthenticateRequest payload, string ip)
{
    lock (UsersFileLock)
    {
        // Re-read inside the lock -- another joiner may have registered between
        // the permission checks and now
        _manager.UserConfig.ReadFromFile();

        var users = _manager.UserConfig.LastRead.Users;
        var key = payload.Username.ToLowerInvariant();

        if (users.TryGetValue(key, out var userData))
        {
            if (string.IsNullOrWhiteSpace(userData.Token))
            {
                // Token was cleared by an admin -- claim it for whoever connects
                // next under this name, so a lost token can be recovered.
                TavernLogger.Warn($"Token re-claimed: '{payload.Username}' (ID {userData.UserId}) from {ip}");
                userData.Token = payload.Token;
            }
            else if (payload.Token != userData.Token)
            {
                TavernLogger.Msg($"Joining user at IP {ip} tried to take username");
                return new AuthPayloads.GenericFail("Name taken by someone else, or you lost the token to your account!");
            }
        }
        else
        {
            TavernLogger.Msg($"Joining user at IP {ip} being allotted a slot in Users.json");

            // Mint from the highest id in the file, never from the count
            // a removed user would otherwise hand its id to the next joiner.
            // Seeded so the first user on a fresh server still gets BaseUserID.

            var nextId = users.Values
                .Select(user => user.UserId)
                .DefaultIfEmpty(BaseUserID - 1)
                .Max() + 1;

            userData = new UserConfig.User
            {
                RegisteredFrom = ip,
                Token = payload.Token,
                UserId = Math.Max(nextId, BaseUserID)
            };

            users[key] = userData;
            TavernLogger.Msg($"New player: '{payload.Username}' (ID {userData.UserId}) from {ip}");
        }

        TavernLogger.Msg("Writing any potential changes during join to file");
        _manager.UserConfig.WriteToFile();

        return new AuthPayloads.AuthenticateOk(userData.UserId, _manager.ServerConfig.LastRead.QuestScene);
    }
}
    private async Task<bool> CheckIfPermitted(string joinerIp, AuthPayloads.AuthenticateRequest payload, Stream stream)
    {
        TavernLogger.Msg($"Checking if joining user {joinerIp} can join");
        // Whitelist
        if (_manager.UserConfig.LastRead.Whitelist.Ips.Count > 0 || _manager.UserConfig.LastRead.Whitelist.Usernames.Count > 0)
        {
            var ipAllowed = _manager.UserConfig.LastRead.Whitelist.Ips.Contains(joinerIp);
            var nameAllowed = _manager.UserConfig.LastRead.Whitelist.Usernames.Any(u => string.Equals(u, payload.Username, StringComparison.OrdinalIgnoreCase));

            if (!ipAllowed && !nameAllowed)
            {
                TavernLogger.Msg($"Joining user at {joinerIp} was not on the whitelist");
                await WriteResponse(stream, new AuthPayloads.NotWhitelisted());
                return false;
            }
        }

        // Blacklist
        if (_manager.UserConfig.LastRead.Blacklist.Ips.Count > 0 || _manager.UserConfig.LastRead.Blacklist.Usernames.Count > 0)
        {
            var ipBlocked = _manager.UserConfig.LastRead.Blacklist.Ips.Contains(joinerIp);
            var nameBlocked = _manager.UserConfig.LastRead.Blacklist.Usernames.Any(u => string.Equals(u, payload.Username, StringComparison.OrdinalIgnoreCase));

            if (ipBlocked || nameBlocked)
            {
                TavernLogger.Msg($"Joining user at {joinerIp} was on the blacklist");
                await WriteResponse(stream, new AuthPayloads.GenericFail("Blacklisted"));
                return false;
            }
        }

        // Password
        if (!string.IsNullOrWhiteSpace(_manager.ServerConfig.LastRead.PasswordHash))
        {
            if (string.IsNullOrWhiteSpace(payload.Password))
            {
                TavernLogger.Msg($"Joining user at {joinerIp} gave no password to server");
                await WriteResponse(stream, new AuthPayloads.NeedsPassword());
                return false;
            }

            // Hash the user provided password again to match Tavern Launcher's password setup
            if (BackendUtils.HashDigest(payload.Password) != _manager.ServerConfig.LastRead.PasswordHash)
            {
                TavernLogger.Msg($"Joining user at {joinerIp} gave the wrong password");
                await WriteResponse(stream, new AuthPayloads.WrongPassword());
                return false;
            }
        }

        // IP limit
        if (_manager.ServerConfig.LastRead.EnforceIpLimit)
        {
            var matchingIpCount = _manager.UserConfig.LastRead.Users.Count(user => user.Value.RegisteredFrom == joinerIp);
            if (matchingIpCount > 4)
            {
                await WriteResponse(stream, new AuthPayloads.GenericFail("Too many accounts with same origin"));
                return false;
            }
        }

        TavernLogger.Msg($"Joining user at {joinerIp} passed all authentication checks");
        return true;
    }

    private async Task ManageWhitelistApplicationRequest(Stream stream, JObject payload, TcpClient joiner)
    {
        if (CommandLineArguments.Contains(TavernArgs.DontManageAuth))
        {
            TavernLogger.Msg("Ignoring whitelist application -- TavernLauncher is managing auth for this instance.");
            return;
        }

        try
        {
            var username = payload.Value<string>("username");
            if (string.IsNullOrWhiteSpace(username))
            {
                await WriteResponse(stream, new AuthPayloads.GenericFail("Missing username"));
                return;
            }

            var joinerIp = ((IPEndPoint)joiner.Client.RemoteEndPoint).Address.ToString();
            TavernLogger.Msg($"Whitelist application from {username} at {joinerIp}");

            bool alreadyPending;

            lock (WhitelistRequestsFileLock)
            {
                _manager.WhitelistRequests.ReadFromFile(); // pick up anything the owner's panel already cleared
                var requests = _manager.WhitelistRequests.LastRead.Requests;

                alreadyPending = requests.Exists(r =>
                    string.Equals(r.Username, username, StringComparison.OrdinalIgnoreCase) && r.Ip == joinerIp);

                if (!alreadyPending)
                {
                    requests.Add(new WhitelistRequestList.WhitelistRequest
                    {
                        Username = username,
                        Ip = joinerIp,
                        AppliedAt = DateTime.UtcNow.ToString("o"),
                    });
                    _manager.WhitelistRequests.WriteToFile();
                }
            }

            await WriteResponse(stream, new AuthPayloads.WhitelistApplicationReceived(!alreadyPending));
        }
        catch (Exception e)
        {
            TavernLogger.Error($"Error managing whitelist application {e}");
            await WriteResponse(stream, new AuthPayloads.GenericFail("Error processing application"));
        }
    }

    private async Task WriteResponse(Stream stream, object response)
    {
        try
        {
            var serializedResponse = JsonConvert.SerializeObject(response);
            var encodedResponse = Encoding.UTF8.GetBytes(serializedResponse);

            TavernLogger.Msg($"Writing response to joining client: {serializedResponse}");

            await stream.WriteAsync(encodedResponse, 0, encodedResponse.Length);
        }
        catch (Exception e)
        {
            TavernLogger.Error($"Error when sending auth OK {e}");
            throw;
        }
    }
}