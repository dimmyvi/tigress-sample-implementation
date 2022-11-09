---

title: "Transfer Digital Credentials Securely: sample implementation and threat model"
abbrev: "tigress-sample-implementation"
category: info

docname: draft-tigress-sample-implementation-latest
submissiontype: IETF
number:
date:
v: 3
area: ART
workgroup: Tigress
keyword: Internet-Draft
venue:
#  group: WG
#  type: Working Group
#  mail: tigress@ietf.org
#  arch: "https://mailarchive.ietf.org/arch/browse/tigress"
  github: "dimmyvi/tigress-sample-implementation"
  latest: "https://github.com/dimmyvi/tigress-sample-implementation"

author:
 -
    ins: D. Vinokurov
    fullname: Dmitry Vinokurov
    organization: Apple Inc
    email: dvinokurov@apple.com
 -
    ins: A. Bulgakov
    name: Alexey Bulgakov
    organization: Apple Inc
    email: abulgakov@apple.com
 -
    ins: J.L. Giraud
    name: Jean-Luc Giraud
    organization: Apple Inc
    email: jgiraud@apple.com
 -
    ins: C. Astiz
    name: Casey Astiz
    organization: Apple Inc
    email: castiz@apple.com
 -
    ins: A. Pelletier
    name: Alex Pelletier
    organization: Apple Inc
    email: a_pelletier@apple.com
 -
    ins: J. Hansen
    name: Jake Hansen
    organization: Apple Inc
    email: jake.hansen@apple.com

normative:
  Tigress-00:
    author:
    -
      ins: D. Vinokurov
      name: Dmitry Vinokurov
    -
      ins: M. Byington
      name: Matt Byington
    -
      ins: M. Lerch
      name: Matthias Lerch
    -
      ins: A. Pelletier
      name: Alex Pelletier
    -
      ins: N. Sha
      name: Nick Sha
    title: "Transfer Digital Credentials Securely"
    date: 2022-09
    target: https://datatracker.ietf.org/doc/draft-art-tigress/


  CCC-Digital-Key-30:
    author:
      org: Car Connectivity Consortium
    title: "Digital Key Release 3"
    date: 2022-07
    target: https://carconnectivity.org/download-digital-key-3-specification/

  NIST-800-63B:
    author:
      org: NIST
    title: "NIST Special Publication 800-63B, Digital Identity Guidelines"
    date: 2022-11
    target: https://pages.nist.gov/800-63-3/sp800-63b.html

  WebAuthn-2:
    author:
      org: W3
    title: "Web Authentication - An API for accessing Public Key Credentials - Level 2"
    date: 2021-04
    target: https://www.w3.org/TR/webauthn-2/


informative:


--- abstract

This document describes a sample implementation of Tigress internet draft {{Tigress-00}} and a threat model of this implementation.


--- middle

# Introduction

This document provides a sample implementation and threat model for Tigress draft {{Tigress-00}}.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

- DCK - Digital Car Key
- AP - Application Processor
- TTL - Time To Live
- AAA - Apple Anonymous Attestation - a subtype of WebAuthn {{WebAuthn-2}}
- PKI - public Key Infrastructure
- UUID - a unique identifier defined in {{!RFC4122}}
- SMS - Short Message Service
- OS - Operating System
- URI - Uniform Resource Identifier
- RNG - Random Number Generator

# Sample Implementation - Digital Car Key sharing example.

- An owner device (Sender) starts sharing flow with selection of credential entitlements for the key shared - e.g. access entitlements (allow open the car, allow start the engine, allow to drive the car), time of sharing - e.g. from 09/01/2022 to 09/03/2022, then generates a KeyCreationRequest (per {{CCC-Digital-Key-30}} ).

- The owner device generates a new symmetric encryption key (Secret) and encrypts the data of KeyCreationRequest. Then generates an attestation data, that follows a WebAuthn API {{WebAuthn-2}}, specific to Apple - AAA, which covers the encrypted content. Owner device makes a call to Relay server (Intermediary) - createMailbox, passing over the encrypted content, device attestation, mailbox configuration (mailbox time-to-live, access rights - Read/Write/Delete), preview (display information) details, its push notification token and a unique deviceClaim.

- Relay server verifies device attestation using WebAuthn verification rules specific to attestation data used, including verifying device PKI certificate in attestation blob. Relay server creates a mailbox, using mailboxConfiguration received in the request and stores encrypted content in it.

- The mailbox has a time-to-live which defines when it is to expire and be deleted by the Relay server. This time is limited by the value that can be considered both sufficient to complete the transfer and secure to against brute force attacks on the encrypted content - e.g. 48 hours.

- Relay server generates a unique mailboxIdentifier value, that is hard to predict - e.g. using UUID - and builds a full URL (shareURL) referencing the mailbox - e.g. "https://www.example.com/v1/m/2bba630e-519b-11ec-bf63-0242ac130002", which it returns to the Owner device.

- Owner device locally stores the shareURL and the Secret and sends the shareURL with optional vertical in URL parameter and mandatory secret in Fragment part (e.g. "https://www.example.com/v1/m/2bba630e-519b-11ec-bf63-0242ac130002?v=c#hXlr6aRC7KgJpOLTNZaLsw==") to the Friend’s device (Receiver) over SMS.

- Friend device receives the shareURL in SMS, messaging application makes an automatic GET call to shareURL (excluding Fragment part - Secret) - and fetches a preview (Display Information) html page with OpenGraph tags in the head:

~~~
<html prefix="og: https://ogp.me/ns#">
<head>
 <title>Shared Key</title>
 <meta content="Shared Key" property="og:title"/>
 <meta content="You've been invited to add a shared digital car key to your device." property="og:description"/>
 <meta content="https://example.com/displayInfo/general.png" property="og:url"/>
 <meta content="https://example.com/displayInfo/general.png" property="og:image"/>
 <meta content="200" property="og:image:width"/>
 <meta content="100" property="og:image:height"/>
</head>
</html>
~~~
{: #opengraph-preview-example title="OpenGraph preview of a credential"}

- Messaging application shows the a preview of the DCK on the Friend's device that Owner wants to share with them. User accepts the shareURL by clicking on the preview in the messaging application. Messaging application redirects the user to wallet (credential manager application) using a deep link mechanism embedded into the OS.

- Wallet receives the shareURL with the Secret in the Fragment. Friend device checks if the Relay server is in allow-list of accepted Relay servers.

- Wallet reads secure content from the mailbox using shareURL (without the Fragment part) with ReadSecureContentFromMailbox method, passing a unique deviceClaim with the request. Thus, relay server binds the mailbox (identified by mailboxIdentifier) with the Owner device (with Owner device deviceClaim at the mailbox creation time) and the Friend device (with Friend device deviceClaim at the first time Friend device calls ReadSecureContentFromMailbox for the mailbiox). Now only these 2 devices are allowed to read and write secure content to this particular mailbox. This secures the message exchange and prevents other devices from altering the exchange between Owner and Friend.

- Friend’s device decrypts secure content using Secret and extracts KeyCreationRequest (ref to {{CCC-Digital-Key-30}} specification).

- Friend device generates a KeySigningRequest (ref to {{CCC-Digital-Key-30}} specification), encrypts it with Secret and uploads to the mailbox with UpdateMailbox call to Relay server, providing its unique deviceClaim and push notification token.

- Relay server sends a push notification to Owner’s device via Push Notification Server.

-  Owner device, having received a push notification message,  reads secure content from the mailbox using shareURL with ReadSecureContentFromMailbox method, passing its unique deviceClaim with the request. Owner device decrypts secure content using Secret and extracts KeySigningRequest (ref to {{CCC-Digital-Key-30}} specification).

-  Owner device signs the Friend’s device public key with Owner’s private key and creates a KeyImportRequest (ref to {{CCC-Digital-Key-30}} specification). Owner device encrypts it with the Secret and uploads to the mailbox with UpdateMailbox call to Relay server, providing its unique deviceClaim.

-  Relay server sends a push notification to Friend device via Push Notification Server.

- Friend device, having received a push notification message,  reads secure content from the mailbox using shareURL with ReadSecureContentFromMailbox method, passing its unique deviceClaim with the request. Friend device decrypts secure content using Secret and extracts KeyImportRequest (ref to {{CCC-Digital-Key-30}} specification). Friend device provisions the new credential to the wallet and deletes the mailbox with DeleteMailbox call to the Relay server. As an additional security measure, Friend device asks for a verification code (PIN code) generated by Owner device and communicated to Friend out-of-band.


# Threat Model

Threat model for the sample implementation is provided at the following URL:
[threat_model]: https://github.com/dimmyvi/tigress-sample-implementation/blob/main/threat_model.png "Threat model for Tigress sample implementation"

| Item |   Asset    |   Threat               |     Impact                       |     Mitigation                           | Comment |
|:-----|:-----------|:-----------------------|:---------------------------------|:-----------------------------------------|:--------|
|   1  | Owner's DCK| Kicking-off arbitrary key sharing by spoofing user identity | DCK becomes shared with arbitrary user/adversary allowing them access to the Owner's car| 1) User auth (face/touch ID), 2) Secure Intent |   |
| 2    | Content on Intermediary server | Content recovery by brute forcing secret | Exposure of encrypted content and key redemption | 1) Strong source of randomness for salt, 2) At least 128 bit key length, 3) Limitted TTL of the mailbox |   |
| 3    | Content on Intermediary server | Content recovery by intercepting secret | Ability to decrypt content on Intermediary server | 1) Physical separation between content and secret, e.g. secret sent as URI fragment to recipient, 2) Optional second factor(e.g. Device PIN, Activation Options - please refer to CCC Technical Specification) can be proposed to the user via user notification based on security options of selected primary sharing channel (used to share URL with secret) |  |
| 4    | Content on Intermediary server | Access to content by multiple arbitrary  users/devices | 1) Adversary can go to partner and redeem the shared key, 2) Adversary can send push notifications | 1) Mailboxes identified by version 4 UUID defined in {{!RFC4122}}(hard to guess/bruteforce), 2) Mailboxes 'tied' to sender and recipient (trust on first use via deviceClaim), 3) TTL limit for mailboxes, 4) Mailboxes deleted after pass redemption |   |
 5    | Content on Intermediary server | Compromised Intermediary server | 1) Adversary can redeem the sharedKey, 2) Adversary can send push notifications | 1) Separation between content and secret, e.g. secret sent as URI fragment to recipient, 2) TTL limit for mailboxes |    |
| 6    | Content on Intermediary server and Push Tokens | Unauthenticated access to mailbox on Intermediary server | 1) Adversary can redeem the sharedKey, 2) Adversary can send push notifications | 1) Mailboxes identified by version 4 UUID defined in {{!RFC4122}}(hard to guess/bruteforce), 2) Mailboxes 'tied' to sender and recipient (trust on first use via deviceClaim), 3) TTL limit for mailboxes, 4) Mailboxes deleted after pass redemption |   |
| 7    | Content on Intermediary server | User stores non-credential information in mailbox (e.g. "cat pictures") | Service abuse, Adversary can use Intermediary server as cloud storage | 1) Mailboxes have size limit, 2) Mailboxes have TTL |   |
| 8    | Device PIN | Receiver device compromised (redemption before friend) | Device PIN can exposure and forwarding to an advarsary | Activation Options as defined in {{CCC-Digital-Key-30}}, Section 11.2 Sharing Principles, subsection 11.2.1.3. Activation Options |    |
| 9    | Device PIN | Weak PIN can be easily guessed | Anyone with share URL in their possession can guess the PIN and redeem the key | 1) Use of strong RNG as a source to generate Device PIN, 2) Long enough PIN (e.g. 6 digits) as per {{NIST-800-63B}} recommendations, 3) Limit the number of retries (e.g. Device PIN retry counter + limit) as per {{NIST-800-63B}} recommendations | {{NIST-800-63B}}, section 5.1.1.1 Memorized Secret Authenticators |
| 10    | Device PIN | Eavesdropping on weak msg channels/app | PIN exposure would allow one with possession of share URL and Secret to redeem key | In person, out of band PIN transfer, e.g. voice channel |  |
| 11    | Device PIN | PIN recovery via timing attack | Adversary with shared URL in possession can recover PIN based on the response delay, in the case where the PIN verification is not invariant | 1) Time invariant compare, 2) PIN retry counter/limit |  |
| 12    | Device PIN retry counter/limit | Device PIN brute force | Device PIN successful guess | 1) Use of strong RNG as a source to generate Device PIN, 2) Long enough PIN (e.g. 6 digits) as per  {{NIST-800-63B}} recommendations, 3) Limit the number of retries (e.g. DEvice PIN retry counter + limit) as per {{NIST-800-63B}} recommendations | {{NIST-800-63B}}, section 5.1.1.1 Memorized Secret Authenticators |
| 13    | Sharing Invitation | Messaging channel eavesdropping  | Share invitation forwarding and DCK redemtion by malicious party | 1) Send invitation and Device PIN via different channels, e.g. Device PIN can be shared out of band (over voice), 2) Use of E2E encrypted msg apps/chhannel |   |
| 14    | Sharing Invitation | Voluntary/Involuntary forwarding by Friend | DCK redemption before Friend | Use of messaging apps with anti-forwarding mechanisms(e.g. hide link, copy/past prevention) |   |
| 15    | Sharing Invitation | Friend device compromise allow malware to forward invitation to an adversary | Share invitation forwarding and key redemption by malicious party | Activation Options as defined in {{CCC-Digital-Key-30}}, Section 11.2 Sharing Principles, subsection 11.2.1.3. Activation Options |   |
| 16    | Sharing Invitation | User mistakenly shares with the wrong person | DCK redemption by adversary/not intended user | 1) Send invitation and Device PIN via different channels, e.g. Device PIN can be shared out of band (over voice), 2) DCK revocation |   |
| 17    | Sharing Invitation | Owner device compromise allow malware to forward invitation to an adversary | Share invitation forwarding and key redemption by malicious party | Activation Options as defined in {{CCC-Digital-Key-30}}, Section 11.2 Sharing Principles, subsection 11.2.1.3. Activation Options |   |
| 18    | Sharing Invitation | Friend device OEM account take over | DCK provisioning on adversary's device | 1) Binding to deviceClaim, 2) Device PIN shared out of band, 3) Activation Options as defined in {{CCC-Digital-Key-30}}, Section 11.2 Sharing Principles, subsection 11.2.1.3. Activation Options |   |
| 19    | User's credentials, payment card details, etc| Phishing attacks leveraging malicious Java Script in preview page | 1) Preview page URL fragement contains encryption key - meaning malicious JS could use key to decrypt contents, 2) Malicious Java Script can phish for user credentials, payment card information, or other sensitive data | 1) Properly vet Java Script that is embedded in the preview page, 2) Define strong content security policy |   |


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
