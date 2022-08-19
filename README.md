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
in mind, allowing fast prototyping by offering sensible defaults, ready-to-use
implementations and HTML templates required for redirect based flows.

Nearly every aspect of the code of this OAuth2 implementation is modifiable.

__Disclaimer: this is work in progress. That means there will still be breaking changes!__ 

## Terminology

If you are already an experienced OAuth2 user, you can skip this paragraph.

- Resource Owner: the user who owns a resource, e.g. if Alex has photos stored on a server, Alex is the resource owner.
- Client: the app that wants to access a resource.
- User-Agent: some kind of client able to execute HTTP requests, but the actual client must not be able to access its storage. Typically a web browser.
- Authorization Server: the heart of all authorization and authentication flows.
- Resource Server: the server that actually has resource and is willing to supply it on the condition of correct authorization.
- PKCE: (pronounced like 'pixie'): stands for _Proof Key for Code Exchange_ and is an extension of top of OAuth2 used for public clients using Authorization Code Grant mitigating authorization code interception attacks.
- OIDC: stands for _OpenID Connect_, an additional identity layer on top of OAuth2 which allows clients to verify the identity of resource owners and to obtain basic profile information about those resource owners.

## Grant types

So far, __goauth2__ supports the following grant types: 

 - [ ] Client Credentials Grant
 - [ ] Resource Owner Credentials Grant
 - [ ] Implicit Grant
 - [X] Device Code Grant
 - [ ] Authorization Code Grant

## Explanations of grant types

### Client Credentials Grant
### Resource Owner Credentials Grant
### Implicit Grant
### Device Code Grant

It is also called _Device Authorization Grant_ and _Device Flow_.
The flow schema looks as follows:

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

## Examples

Examples can be found in the `examples` folder. usually examples consist of a server
and a client implementation.
