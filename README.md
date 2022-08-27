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

## The Big Why

> "So, why should I use OAuth at all? I have my username and password, that's all I need. And all of this looks so complicated anyway!"
> 
> Ghandi, probably around 2015


Well, for confidential clients, which can keep a secret, this is perfectly fine and dandy.
The main problem OAuth2 tries to solve is to have a uniform way to handle authorization 
(and authentication by extension) for public clients like native (mobile) apps or SPAs, which cannot
keep a secret.

By using either the Implicit Grant (which was specifically made for Javascript SPAs) or the 
Authorization Code Grant, the app never even sees your credentials, which adds a whole new layer of
security.

And classic credentials like username and password will typically not work out if you want to access a resource
server; you will need an access token. This access token is basically a password, and as such should
be treated as confidential data.

But access tokens have a few advantages:
* They can be revoked (and you don't need to change your password for that)
* They have a short lifetime (which drastically reduces the time an attack can use it for malicious purposes), but can be refreshed
* They have a reduced set of permissions, called scopes. Only those scopes YOU authorized the app to
use can actually be accessed using the access token.

## Terminology

If you are already an experienced OAuth2 user, you can skip this paragraph.

- Resource Owner: the user who owns a resource.
- Client: the app that wants to access a resource.
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
 - [X] Device Code Grant (with example code)
 - [ ] Authorization Code Grant
 - [ ] Authorization Code Grant with Proof Key for Code Exchange

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
         |    Resource Owner
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
          :                                     |                |
         (C) User Code & Verification URI       |                |
          :                                     |                |
          v                                     |                |
    +----------+                                |                |
    | End User |                                |                |
    |    at    |<---(D)-- End user reviews  --->|                |
    |  Browser |          authorization request |                |
    +----------+                                +----------------+

### Authorization Code Grant

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

The flow schema looks as follows:

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
