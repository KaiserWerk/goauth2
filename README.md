# goauth2

> The OAuth 2.0 authorization framework enables a third-party
application to obtain limited access to an HTTP service, either on
behalf of a resource owner by orchestrating an approval interaction
between the resource owner and the HTTP service, or by allowing the
third-party application to obtain access on its own behalf.

From https://www.rfc-editor.org/rfc/rfc6749

---

## Introduction

goauth2 is a Go library to create OAuth2 servers. It is made with ease-of-use 
in mind, allowing fast prototyping by offering useful defaults, ready-to-use in-memory storage
implementations and basic HTML templates required for redirect based authorization flows.

Nearly every aspect of this OAuth2 implementation is modifiable.

__Disclaimer: this is work in progress. That means there will still be breaking changes!__ 

## Terminology

If you are already an experienced OAuth2 user, you can skip this paragraph.

- Resource Owner: the user who owns a resource.
- Client: the app that wants to access a resource.
  - Confidential Client: a client that can keep a secret, e.g. server-side web apps
  - Public Client: a client that cannot keep a secret, e.g. mobile or desktop apps 
- User-Agent: some kind of client able to execute HTTP requests, but the actual client must not be able to access its storage. Typically a web browser.
- Authorization Server: the heart of all authorization and authentication flows.
- Resource Server: the server that actually has resource and is willing to supply it on the condition of correct authorization.
- PKCE: (pronounced 'pixie'): stands for _Proof Key for Code Exchange_ and is an extension of top of OAuth2 used for public clients using Authorization Code Grant mitigating authorization code interception attacks.
- OIDC: stands for _OpenID Connect_, an additional identity layer on top of OAuth2 which allows clients to verify the identity of resource owners and to obtain basic profile information about those resource owners.


## Grant Types

So far, __goauth2__ supports the following grant types: 

- [X] Client Credentials Grant
- [X] Resource Owner Password Credentials Grant
- [X] Implicit Grant
- [X] Device Code Grant
- [X] Authorization Code Grant
- [X] Authorization Code Grant with Proof Key for Code Exchange
- [ ] OpenID Connect

## Explanations of Grant Types

### Client Credentials Grant

The client can request an access token using only its client credentials when the client is 
requesting access to the protected resources under its control, or those of another resource 
owner that have been previously arranged with the authorization server. A typical use-case is
machine-to-machine communication.

The client credentials grant MUST only be used by confidential clients.

    +---------+                                  +---------------+
    |         |                                  |               |
    |         |>--(A)-- Client Authentication -->| Authorization |
    | Client  |                                  |     Server    |
    |         |<--(B)---- Access Token ---------<|               |
    |         |                                  |               |
    +---------+                                  +---------------+

### Resource Owner Password Credentials Grant

The resource owner password credentials grant type is suitable in cases where the resource owner has a 
trust relationship with the client, such as the device operating system or a highly privileged 
application. The authorization server should take special care when enabling this grant type and 
only allow it when other flows are not viable.

This grant type is suitable for clients capable of obtaining the resource owner’s credentials 
(username and password, typically using an interactive form). It is also used to migrate existing 
clients using direct authentication schemes such as HTTP Basic or Digest authentication to OAuth 
by converting the stored credentials to an access token.

    +----------+
    | Resource |
    |  Owner   |
    |          |
    +----------+
         v
         |  Resource Owner
        (A) Password Credentials
         |
         v
    +---------+                                  +---------------+
    |         |>--(B)---- Resource Owner ------->|               |
    |         |         Password Credentials     | Authorization |
    | Client  |                                  |     Server    |
    |         |<--(C)---- Access Token ---------<|               |
    |         |    (w/ Optional Refresh Token)   |               |
    +---------+                                  +---------------+

### Implicit Grant

The implicit grant type is used to obtain access tokens (it does not support the issuance of 
refresh tokens) and is optimized for public clients known to operate a particular redirection 
URI. These clients are typically implemented in a browser using a scripting language such as 
JavaScript.

Unlike the authorization code grant type, in which the client makes separate requests for 
authorization and for an access token, the client receives the access token as the result 
of the authorization request.

The implicit grant type does not include client authentication, and relies on the presence 
of the resource owner and the registration of the redirection URI. Because the access token 
is encoded into the redirection URI, it may be exposed to the resource owner and other 
applications residing on the same device.

    +----------+
    | Resource |
    |  Owner   |
    |          |
    +----------+
         ^
         |
        (B)
    +----|-----+          Client Identifier     +---------------+
    |         -+----(A)-- & Redirection URI --->|               |
    |  User-   |                                | Authorization |
    |  Agent  -|----(B)-- User authenticates -->|     Server    |
    |          |                                |               |
    |          |<---(C)--- Redirection URI ----<|               |
    |          |          with Access Token     +---------------+
    |          |            in Fragment
    |          |                                +---------------+
    |          |----(D)--- Redirection URI ---->|   Web-Hosted  |
    |          |          without Fragment      |     Client    |
    |          |                                |    Resource   |
    |     (F)  |<---(E)------- Script ---------<|               |
    |          |                                +---------------+
    +-|--------+
      |    |
     (A)  (G) Access Token
      |    |
      ^    v
    +---------+
    |         |
    |  Client |
    |         |
    +---------+

### Device Code Grant

It is also called _Device Authorization Grant_ and _Device Flow_.

The Device Code grant type is used by browser-less or input-constrained devices in the device flow 
to exchange a previously obtained device code for an access token. It can also be used for
applications that cannot handle redirects well, like desktop applications.

    +----------+                                +----------------+
    |          |>---(A)-- Client Identifier --->|                |
    |          |                                |                |
    |          |<---(B)-- Device Code,      ---<|                |
    |          |          User Code,            |                |
    |  Device  |          & Verification URI    |                |
    |  Client  |                                |                |
    |          |  [polling]                     |                |
    |          |>---(E)-- Device Code       --->|                |
    |          |          & Client Identifier   |                |
    |          |                                |  Authorization |
    |          |<---(F)-- Access Token      ---<|     Server     |
    +----------+   (& Optional Refresh Token)   |                |
          v                                     |                |
          |                                     |                |
         (C) User Code & Verification URI       |                |
          |                                     |                |
          v                                     |                |
    +----------+                                |                |
    | End User |                                |                |
    |    at    |<---(D)-- End user reviews ---->|                |
    |  Browser |          authorization request |                |
    +----------+                                +----------------+

### Authorization Code Grant

The authorization code is a temporary code that the client will exchange for an access token. The code 
itself is obtained from the authorization server where the user gets a chance to see what  
information the client is requesting, and approve or deny the request.

The authorization code flow offers a few benefits over the other grant types. When the user 
authorizes the application, they are redirected back to the application with a temporary code 
in the URL. The application exchanges that code for the access token. When the application 
makes the request for the access token, that request can be authenticated with the client secret, 
which reduces the risk of an attacker intercepting the authorization code and using it themselves. 
This also means the access token is never visible to the user or their browser, so it is the 
most secure way to pass the token back to the application, reducing the risk of the token leaking 
to someone else.

    +----------+
    | Resource |
    |   Owner  |
    |          |
    +----------+
         ^
         |
        (B)
    +----|-----+          Client Identifier      +---------------+
    |         -+----(A)-- & Redirection URI ---->|               |
    |  User-   |                                 | Authorization |
    |  Agent  -+----(B)-- User authenticates --->|     Server    |
    |          |                                 |               |
    |         -+----(C)-- Authorization Code ---<|               |
    +-|----|---+                                 +---------------+
      |    |                                         ^      v
     (A)  (C)                                        |      |
      |    |                                         |      |
      ^    v                                         |      |
    +---------+                                      |      |
    |         |>---(D)-- Authorization Code ---------'      |
    |  Client |          & Redirection URI                  |
    |         |                                             |
    |         |<---(E)----- Access Token -------------------'
    +---------+       (w/ Optional Refresh Token)

### Authorization Code Grant with Proof Key for Code Exchange

PKCE (described in [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) is typically used in conjunction with the Authorization Code Grant.

Before redirecting the user to the authorization server, the client first generates a secret code 
verifier and challenge.

The code verifier is a cryptographically random string using the characters A-Z, a-z, 0-9, and the 
punctuation characters -._~ (hyphen, period, underscore, and tilde), between 43 and 128 characters long.

Once the client has generated the code verifier, it uses that to create the code challenge. For 
devices that can perform a SHA256 hash, the code challenge is a BASE64-URL-encoded string of the 
SHA256 hash of the code verifier. Otherwise, the same verifier string is used as the challenge.

When exchanging the code for the access token, the code verifier must be sent over as well. The server
will calculate the BASE64-URL-encoded string of the SHA256 hash of the code verifier and check if the
result matches the initial code challenge.

                                              +-------------------+
                                              |   Authz Server    |
    +--------+                                | +---------------+ |
    |        |--(A)- Authorization Request ---->|               | |
    |        |       + t(code_verifier), t_m  | | Authorization | |
    |        |                                | |    Endpoint   | |
    |        |<-(B)---- Authorization Code -----|               | |
    |        |                                | +---------------+ |
    | Client |                                |                   |
    |        |                                | +---------------+ |
    |        |--(C)-- Access Token Request ---->|               | |
    |        |          + code_verifier       | |    Token      | |
    |        |                                | |   Endpoint    | |
    |        |<-(D)------ Access Token ---------|               | |
    +--------+                                | +---------------+ |
                                              +-------------------+

### Refresh Token Grant

Technically, this is not an actual authorization grant, but a renewal process for previously
performed authorization.

If valid and authorized, the authorization server MAY issue an access token as described in 
[Section 5.1](https://tools.ietf.org/html/rfc6749#section-5.1) of RFC 6749. 

The authorization server MAY issue a new refresh token, in which case the client MUST discard 
the old refresh token and replace it with the new refresh token. The authorization server 
MAY revoke the old refresh token after issuing a new refresh token to the client. If a new 
refresh token is issued, the refresh token scope MUST be identical to that of the refresh 
token included by the client in the initial request.

    +--------+                      +--------------+
    |        |                      |              |
    | Client |--(A) Refresh Token ->| Authz Server |
    |        |                      |              |
    |        |<--(B) New token(s) --|              |
    |        |                      |              |
    +--------+                      +--------------+

## Examples

Examples can be found in the `examples` folder and consist of a server
and a client implementation.
They should be quite self-explanatory considering the abundance of code comments and links
to the RFCs. If there are still things unclear, please open an issue and I will try to address it.

The following examples are currently available:

- [X] Client Credentials Grant
- [X] Resource Owner Password Credentials Grant
- [X] Implicit Grant
- [X] Device Code Grant
- [ ] Authorization Code Grant
- [ ] Authorization Code Grant with Proof Key for Code Exchange

## Security Considerations
Source: [oauth2.com](https://www.oauth.com/oauth2-servers/token-introspection-endpoint/)

### Token Fishing
If the introspection endpoint is left open and un-throttled, it presents a means for an attacker to 
poll the endpoint fishing for a valid token. To prevent this, the server must either require 
authentication of the clients using the endpoint, or only make the endpoint available to internal 
servers through other means such as a firewall.

Note that the resources servers are also a potential target of a fishing attack, and should take 
countermeasures such as rate limiting to prevent this.

### Caching
Consumers of the introspection endpoint may wish to cache the response of the endpoint for performance 
reasons. As such, it is important to consider the performance and security trade-offs when deciding 
to cache the values. For example, shorter cache expiration times will result in higher security since 
the resource servers will have to query the introspection endpoint more frequently, but will result 
in an increased load on the endpoint. Longer expiration times leave a window open where a token may 
actually be expired or revoked, but still be able to be used at a resource server for the remaining 
duration of the cache time.

One way to mitigate this problem is for consumers to never cache the value beyond the expiration 
time of the token, which would have been returned in the “exp” parameter of the introspection response.

### Limiting Information
The introspection endpoint does not necessarily need to return the same information for all queries 
of the same token. For example, two different resource servers (if they authenticate themselves 
when making the introspection request) may get different views of the state of the token. This can 
be used to limit the information about the token that is returned to a particular resource server. 
This makes it possible to have tokens that can be used at multiple resource servers without other 
servers ever knowing it is possible to be used at any other server.