<div align=center>
   <img width=128 alt="CollapseIRC" src="https://github.com/user-attachments/assets/4a9b1d2b-4b78-423d-b83e-4f73e29d7bfd" />
   <h1>CollapseIRCServer</h1>
</div>

<p align=center>A lightweight, secure IRC server written in Go with JSON-based protocol (NDJSON), designed for CollapseLoader integration.</p>

### Core Features

-   **JSON Protocol**: Structured, robust communication using NDJSON.
-   Real-time global chat.
-   Private messaging (@msg, @r).
-   Role-based colors and permissions.
-   Ban/unban system.
-   Mute system (mute users or IPs to block public messages).
-   Admin profile IP info (admins can view the IP for users/guests when available).
-   System messages.

### User Roles & Colors

| Role      | Prefix | Color  | Permissions          |
| --------- | ------ | ------ | -------------------- |
| User      | §f     | White  | Basic chat           |
| Tester    | §a     | Green  | —                    |
| Admin     | §c     | Red    | Ban/unban users      |
| Developer | §6     | Gold   | Send system messages |
| Owner     | §d     | Purple | Full privileges      |

### JSON Protocol Specification

The server uses **NDJSON** (Newline Delimited JSON). Every message is a single line containing a valid JSON object.

#### 1. Authentication (Client -> Server)

Sent immediately after connection.

```json
{
    "op": "auth",
    "token": "YOUR_AUTH_TOKEN",
    "type": "loader", // "loader" or "client"
    "client": "CollapseLoader" // client name
}
```

#### 2. Sending Messages (Client -> Server)

**Chat Message:**

```json
{
    "op": "chat",
    "content": "Hello world!"
}
```

**Commands:**
Commands are sent inside the `content` field starting with `@`:

```json
{
    "op": "chat",
    "content": "@msg User123 hello private!"
}
```

**Ping:**

```json
{ "op": "ping" }
```

#### 3. Receiving Messages (Server -> Client)

**Chat Message:**

```json
{
    "type": "chat",
    "time": "2023-10-01T12:00:00Z",
    "content": "§fUser [§fUser§r]: Hello world!",
    "history": false
}
```

**System/Error Message:**

```json
{
    "type": "system", // or "error", "private"
    "content": "You are connected as guest",
    "time": "..."
}
```

### Available Commands (In Chat)

| Command             | Description                                                                |
| ------------------- | -------------------------------------------------------------------------- |
| @ping               | Check connection (returns PONG)                                            |
| @online             | Show online user count                                                     |
| @who / @list        | List all connected users                                                   |
| @help               | Show help                                                                  |
| @msg <nick> <text>  | Send private message                                                       |
| @r <text>           | Quick reply to last PM                                                     |
| @profile [nickname] | (Admin+) View user profile (shows IP if available; guests show IP locally) |
| @ban <user_id>      | (Admin+) Ban user                                                          |
| @unban <user_id>    | (Admin+) Unban user                                                        |
| @banip <ip>         | (Admin+) Ban IP (by IP or user's current IP)                               |
| @unbanip <ip>       | (Admin+) Unban IP                                                          |
| @mute <user_id>     | (Admin+) Mute a user's public chat                                         |
| @unmute <user_id>   | (Admin+) Unmute a user                                                     |
| @muteip <ip>        | (Admin+) Mute an IP (block public chat)                                    |
| @unmuteip <ip>      | (Admin+) Unmute an IP                                                      |
| @sysmsg <text>      | (Admin/Dev/Owner) System message                                           |

### Quick Start (Docker)

```bash
git clone https://github.com/dest4590/CollapseIRCServer
cd CollapseIRCServer
docker compose up --build -d
```

### Quick Start (Go)

```bash
git clone https://github.com/dest4590/CollapseIRCServer
cd CollapseIRCServer
go run ./src
```

Server listens on port **1338**.
