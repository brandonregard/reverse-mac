# reverse-mac

We want you to write an authenticated API using AWS API Gateway and Lambda.
API will have one endpoint which will reverse a list of MAC addresses.

MAC Address - is a unique identifier assigned to network interfaces cards (wifi, ethernet, bluetooth, etc).

Requirements:
- Use Serverless framework to setup project (Optional, but we use this at SBD)
- Endpoint must be secured using an API Key
- Authorizer should be setup on API Gateway to check the token
- Document your code
- Final project must be submitted within 2 days
- Language can be Javascript or Typescript
- Submit entire project zipped.
- Should have unit tests.

Authorizer Function:

- Should check that the Authorization header is a Bearer <token>
- Token - millisecond timestamp within 10 minutes of the time right now, string doubled, to make the minimum length

Time now = 1602170863123, so Authorization header = Bearer 16021708631231602170863123

- Should check if the timestamp is close to now in the authorizer

Endpoint:

/reverse-mac:

- Should take in an array of macs that need to be reversed.
- mac addresses can be formatted in any of these formats:

"00:A0:C9:14:C8:29"
"00-A0-C9-14-C8-29"
"00A0C914C829"

- Reversed mac address should retain the format of the original mac address:

"00:A0:C9:14:C8:29" -> "29:C8:14:C9:A0:00"
"00-A0-C9-14-C8-29" -> "29-C8-14-C9-A0-00"
"00A0C914C829" -> "29C814C9A000"

input:
- Valid input is below.  Must have 1 or more mac addresses.

{
"macs": [
<mac addresses>
]
}

output:
{
"reversed-macs": [
<reversed mac>
],
"error": [ {
mac: <original mac>,
error: <string>
}
]
}