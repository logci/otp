# WhatsApp OTP Verification API

A minimal Heroku-ready API that connects one WhatsApp session and sends OTP codes to the requested number.

## Endpoint

```text
GET https://your-heroku-app.herokuapp.com/num=COUNTRY_CODE_NUMBER
```

Example:

```text
https://your-heroku-app.herokuapp.com/num=919876543210
```

When the endpoint is called:

1. A 6-digit OTP is generated.
2. The OTP is sent on WhatsApp to the requested number.
3. The API response returns the same OTP and an HTML page with a **Copy OTP** button.
4. The OTP expires after 5 minutes.

WhatsApp message format:

```text
🌸 *Your OTP is: 123456*

⏳ Expires in 5 minutes.
⚠️ Never share this code with anyone.
```

## Optional verify endpoint

```text
GET https://your-heroku-app.herokuapp.com/verify?num=COUNTRY_CODE_NUMBER&otp=123456
```

This verifies the latest unexpired OTP saved in memory for that number.

## Environment variables

| Variable | Required | Description |
| --- | --- | --- |
| `SESSION_ID` | Yes | Gifted WhatsApp session string, for example `Gifted~...` |
| `PORT` | No | Automatically provided by Heroku |

## Run locally

```bash
npm install
npm start
```

## Health check

```text
GET /health
```

Returns whether the server is alive and whether the WhatsApp session is connected.
