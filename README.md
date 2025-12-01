# CollapseIRCServer

A lightweight, secure IRC server written in Go, designed exclusively for CollapseLoader IRC chat integration.

### Core Features

-   Real-time global chat
-   Private messaging (@msg, @r)
-   Role-based colors and permissions
-   Ban/unban system
-   System messages
-   Message cooldown and length limits

### User Roles & Colors

| Role      | Prefix | Color  | Permissions          |
| --------- | ------ | ------ | -------------------- |
| User      | §f     | White  | Basic chat           |
| Tester    | §a     | Green  | —                    |
| Admin     | §c     | Red    | Ban/unban users      |
| Developer | §6     | Gold   | Send system messages |
| Owner     | §d     | Purple | Full privileges      |

### How Authentication Works

1. Client connects using special credentials format:  
   `<user_id>@:@<username>@:@<auth_token>` (optional `@:@<client_name>`)
2. Server calls CollapseLoader API:
    - `https://auth.collapseloader.org/auth/status`
    - `https://auth.collapseloader.org/auth/irc-info/{token}/`
3. If token is valid and user ID matches → user is authenticated and assigned correct role/color.

### Available Commands

| Command            | Description                       |
| ------------------ | --------------------------------- |
| @ping              | Check connection                  |
| @online            | Show online user count            |
| @who / @list       | List all connected users          |
| @help              | Show help                         |
| @msg <nick> <text> | Send private message              |
| @r <text>          | Quick reply to last PM            |
| @ban <user_id>     | (Admin+) Ban user                 |
| @unban <user_id>   | (Admin+) Unban user               |
| @sysmsg <text>     | (Admin+/Dev/Owner) System message |

### Message Format Examples

-   Public: `§asigma§r [§aTester§r]: hi guys`
-   Private (received): `[PM from §cAdmin§r]: hi bro`
-   System: `§c§lSystem§r: §lImportant announcement!§r`

### Quick Start (Docker – Recommended)

```bash
git clone https://github.com/dest4590/CollapseIRCServer
cd CollapseIRCServer
docker compose up --build -d
```

### Quick Start (go)

```bash
git clone https://github.com/dest4590/CollapseIRCServer
cd CollapseIRCServer
go run main.go
```

Server will listen on port **1338**.
