# Login Troubleshooting Guide

## Issue: Login works locally but fails on workers.dev

### Root Cause

The authentication system uses **CSRF (Cross-Site Request Forgery) protection** with a double-submit cookie pattern. This requires:

1. **CSRF token cookie** - Set by the server in a cookie
2. **CSRF token header** - Sent by the client in the `X-CSRF-Token` header
3. **Both must match** - The server validates that the token in the cookie matches the token in the header

### How It Works

#### Normal Flow (Frontend)
1. Frontend makes `GET /api/auth/csrf-token` request
2. Server sets `csrf-token` cookie with JSON: `{"token":"...","timestamp":...}`
3. Server returns token in response body
4. Frontend stores token and sends it in `X-CSRF-Token` header for POST requests
5. Browser automatically sends the cookie with subsequent requests

#### Manual curl Flow
When using curl manually, you must:
1. **First**: Fetch CSRF token and save the cookie
2. **Then**: Use that cookie + token in the login request

### Solution for Manual Requests

#### Step 1: Fetch CSRF Token

```bash
# Fetch CSRF token and save cookies to file
curl -c cookies.txt 'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/csrf-token' \
  -H 'accept: application/json'
```

This will:
- Set the `csrf-token` cookie in `cookies.txt`
- Return the token in the response: `{"success":true,"data":{"token":"...","headerName":"X-CSRF-Token","expiresIn":7200}}`

#### Step 2: Extract Token and Login

```bash
# Extract token from response (or use the token from Step 1 response)
TOKEN=$(curl -s -c cookies.txt 'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/csrf-token' \
  -H 'accept: application/json' | jq -r '.data.token')

# Login using the cookie file and token
curl -b cookies.txt 'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/login' \
  -H 'accept: */*' \
  -H 'content-type: application/json' \
  -H 'x-csrf-token: '"$TOKEN" \
  --data-raw '{"email":"chennachandrika@gmail.com","password":"chandu123"}'
```

### Why Your Current Approach Fails

Your current curl command sends:
- Cookie: `csrf-token=%7B%22token%22%3A%22...%22%2C%22timestamp%22%3A...%7D`
- Header: `x-csrf-token: ...`

**The problem**: The cookie might be:
1. **Expired** - CSRF tokens expire after 2 hours
2. **From a different session** - The cookie might not match the current session
3. **Not properly set** - The cookie might not have been set with the correct domain/path

### Cookie Format

The CSRF token cookie is stored as URL-encoded JSON:
```
csrf-token={"token":"abc123...","timestamp":1767252566236}
```

When URL-encoded in the Cookie header:
```
csrf-token=%7B%22token%22%3A%22abc123...%22%2C%22timestamp%22%3A1767252566236%7D
```

The server:
1. Decodes the cookie value
2. Parses the JSON
3. Extracts the `token` field
4. Compares it with the `X-CSRF-Token` header value

### Differences: Localhost vs workers.dev

| Aspect | Localhost | workers.dev |
|--------|-----------|-------------|
| Protocol | http (secure=false) | https (secure=true) |
| Domain | No domain attribute | No domain attribute |
| SameSite | Lax | Lax |
| Cookie handling | Works with http | Requires https |

### Debugging Steps

1. **Check if CSRF token is being fetched**:
   ```bash
   curl -v 'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/csrf-token'
   ```
   Look for `Set-Cookie: csrf-token=...` in the response headers

2. **Verify cookie is being sent**:
   ```bash
   curl -v -b cookies.txt 'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/login' \
     -H 'x-csrf-token: YOUR_TOKEN' \
     --data-raw '{"email":"...","password":"..."}'
   ```
   Look for `Cookie: csrf-token=...` in the request headers

3. **Check token expiration**:
   The timestamp in the cookie JSON shows when the token was created. Tokens expire after 2 hours (7200 seconds).

### Common Issues

1. **"CSRF validation failed: missing token"**
   - Cookie not being sent → Use `-b cookies.txt` or `-H 'Cookie: ...'`
   - Header not being sent → Use `-H 'X-CSRF-Token: ...'`

2. **"CSRF validation failed: token mismatch"**
   - Cookie token doesn't match header token → Fetch fresh token
   - Using expired token → Fetch new token

3. **Cookie not being set**
   - Domain mismatch → Ensure you're using the correct domain
   - SameSite restrictions → Use `-L` to follow redirects if needed

### Best Practice

Always fetch a fresh CSRF token before making state-changing requests (POST, PUT, DELETE, PATCH):

```bash
# One-liner that fetches token and uses it for login
curl -c cookies.txt -b cookies.txt \
  -H 'x-csrf-token: '"$(curl -s -c cookies.txt 'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/csrf-token' | jq -r '.data.token')" \
  -H 'content-type: application/json' \
  -d '{"email":"chennachandrika@gmail.com","password":"chandu123"}' \
  'https://vibesdk-nxtwave.web-1c2.workers.dev/api/auth/login'
```

### Implementation Details

The CSRF protection is implemented in:
- `worker/services/csrf/CsrfService.ts` - Token generation and validation
- `worker/app.ts` - Middleware that enforces CSRF validation
- `worker/api/controllers/auth/controller.ts` - Login endpoint that rotates token on success
- `src/lib/api-client.ts` - Frontend client that automatically fetches tokens


