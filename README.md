# FISE

A high-performance file sharing backend written in C, using epoll for efficient concurrent connection handling.

This project manages files via APIs, you can find the implementation at [FISE Web](https://github.com/PixelFederico/fise-web) repository.

## Features

- Event-driven architecture using epoll for handling thousands of concurrent connections
- [JWT](https://datatracker.ietf.org/doc/html/rfc7519) authentication with Ed25519 signatures
- Resumable downloads with HTTP Range request support
- File uploads up to 15 GB (Planned to make it configurable)
- Docker deployment support
- Light compiled binary (~44KB)

## Configuration

The only configuration needed is the [JWT](https://datatracker.ietf.org/doc/html/rfc7519) public key for authentication:

| Path | Description |
|------|-------------|
| `/etc/fise/pubkey` | Ed25519 public key (base64url encoded) for JWT verification |

**Note:** If the pubkey file is empty or missing, JWT authentication is automatically disabled and all upload/delete operations will be unauthorized.

To enable authentication, place your Ed25519 public key in `/etc/fise/pubkey`. If using [FISE Web](https://github.com/PixelFederico/fise-web), you can obtain the public key from the `/api/auth/jwks` endpoint (the `x` value).

## API Reference

### Health Check

```
GET /
```

Returns server status.

**Response:**
```json
{"success":"alive"}
```

### Download File

```
GET /api/{id}
```

Downloads a file by its UUID. Supports range requests for resumable downloads.

| Parameter | Description |
|-----------|-------------|
| `id` | The UUID of the file |

**Headers (optional):**

| Header | Description |
|--------|-------------|
| `Range` | Byte range for partial content (e.g., `bytes=0-1024`) |

**Response:**
- `200 OK` - Full file download
- `206 Partial Content` - Range request fulfilled
- `404 Not Found` - File does not exist

### Upload File

```
POST /
```

Uploads a new file. **Requires JWT authentication if enabled.**

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes if enabled | `Bearer <JWT_TOKEN>` |
| `Content-Length` | Yes | File size in bytes |
| `Content-Disposition` | Yes | `form-data; filename="<filename>"` |

**Response:**
- `201 Created` - Returns the UUID of the uploaded file
- `400 Bad Request` - Missing or invalid headers
- `401 Unauthorized` - Invalid or missing JWT

**Example:**
```bash
curl -X POST http://localhost \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "Content-Length: 1024" \
  -H "Content-Disposition: form-data; filename=\"example.txt\"" \
  --data-binary @example.txt
```

### Delete File

```
DELETE /
```

Deletes a file by its UUID. **Requires JWT authentication with admin privileges.**

**Headers:**

| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | Yes if enabled | `Bearer <JWT_TOKEN>` (JWT payload must contain `"admin": true`) |
| `X-FILE-ID` | Yes | The UUID of the file to delete |

**Response:**
- `201 Created` - File deleted successfully
- `400 Bad Request` - Invalid file ID format
- `401 Unauthorized` - Invalid JWT or missing admin privileges
- `404 Not Found` - File does not exist

**Example:**
```bash
curl -X DELETE http://localhost \
  -H "Authorization: Bearer <JWT_TOKEN>" \
  -H "X-FILE-ID: 550e8400-e29b-41d4-a716-446655440000"
```

## Authentication

FISE uses JWT (JSON Web Tokens) with Ed25519 signatures for authentication.

### JWT Requirements

**For uploads (POST):**
- Valid JWT token in `Authorization: Bearer <token>` header
- Token must not be expired (`exp` claim)

**For deletions (DELETE):**
- Valid JWT token in `Authorization: Bearer <token>` header
- Token must not be expired (`exp` claim)
- Token payload must contain `"admin": true`
- File UUID in `X-FILE-ID` header

### JWT Payload Example

```json
{
  "exp": 1735689600,
  "admin": true
}
```

## Docker Deployment

Use the provided [docker-compose.yml](docker-compose.yml) file:

1. Start the service:

   ```bash
   docker compose up -d
   ```

2. (Optional) Add your JWT public key and restart the container:

   ```bash
   echo "your-public-key" > data/pubkey
   ```
   ```bash
   docker compose restart
   ```

### Volumes

| Host Path | Container Path | Description |
|-----------|----------------|-------------|
| `./data/files` | `/var/lib/fise/api` | File storage directory |
| `./data` | `/etc/fise` | Configuration directory (contains `pubkey`) |

## Manual Development

### Prerequisites

- GCC compiler
- OpenSSL development libraries (`libssl-dev` / `openssl-dev`)
- UUID library (`uuid-dev` / `util-linux-dev`)

**Debian/Ubuntu:**
```bash
apt install gcc libssl-dev uuid-dev
```

**Alpine:**
```bash
apk add gcc musl-dev openssl-dev util-linux-dev
```

### Build

```bash
gcc -Wall -W -O2 main.c -luuid -lcrypto -o fise
```

### Run

```bash
./fise
```

The server will start on port 80. Make sure the required directories exist:
- `/var/lib/fise/api/` - File storage
- `/etc/fise/pubkey` - JWT public key (optional)

## TODO

- [ ] Make each response asynchronous
- [ ] Add API timeout system
- [ ] Use more files in the source instead of only one big file
- [ ] Make a configuration file
- [ ] Add more crypto signature algorithms support for JWT
- [ ] Suggest your features!

## Contributing

Interested in contributing? Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.
