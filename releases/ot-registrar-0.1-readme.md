# OT Registrar 0.1

This is the Registrar implemented and used for testing OpenThread-1.2 _Commercial Extension_ features.

It currently follows Thread-1.2 draft7 and [BRSKI draft22](https://tools.ietf.org/html/draft-ietf-anima-bootstrapping-keyinfra-22).

OT Registrar includes four components in a single Java package:

- **The registrar**

  The registrar implements all mandatory resources required by Thread-1.2 draft7 and `COM_TOK.req` API for commissioner requesting `Commissioner Token`, but currently doesn't conform to the BRSKI drafts:
  - No logging of registered devices
  - Certificate revoking is not implemented

- **Pledge** (Simulated Thread Joiner)

  A simulated pledge/joiner is created to verify implementation of the registrar.

- **MASA server**

  A simple stateless MASA server that implements the BRSKI voucher request API, without any logging (audit log). The registrar supports multiple MASA servers.

- **Tools for generating certificates**

  The tools currently generate certificates used by the registrar, MASA, commissioner, and devices.

## Claims

The payloads presented here is only for illustration. **They must not be used in production or testing**.

## Platform

Written in Java, the registrar runs where Java does:

- Linux
- Windows
- macOS
- Raspberry Pi

## Performance

While this is the first version of OT Registrar, it can handle hundreds parallel requests.

## Certificates

Certificates hierarchy:

- Domain CA certificate is self-signed;
- Registrar and commissioner certificate is directly signed by Domain CA, thus has a certificate path length of 2;
- MASA CA certificate is self-signed;
- device certificates are directly signed by MASA CA, thus has a certificate path length of 2;

## BRSKI API

OT Registrar implements all mandatory RESTful APIs needed by Thread CCM joining.

### Initial DTLS handshake

The Registrar **does not** include the `Domain CA certificate` in DTLS `CertificateMessage`, implementation depends on this root certificate maybe fail.

### Request voucher

Resource: `/.well-known/est/rv`, `CoAP POST`

The registrar performs voucher request validation as demanded in BRSKI draft and sends the signed voucher request to a MASA server. The MASA server returns a voucher response signed by its private key.

#### Constrained voucher SID

The voucher and voucher request SID used by this registrar is defined in Thread-1.2 draft7.

#### Response

- Registrar responses with a `constrained voucher` signed by MASA CA.
- The `constrained voucher` includes the `pinned-domain-certificate` which is used to verify the provisionally accepted registrar certificate.

### Request CSR attributes

Resource: `/.well-known/est/att`, `CoAP GET`

A device requests CSR attributes that must be included in the CSR. Currently, registrar requires two:

```text
[
    // ATTRIBUTE: {ecPublicKey, prime256v1}
    {"1.2.840.10045.2.1" : "1.2.840.10045.3.1.7"},

    // OID: ecdsa-with-SHA256
    "1.2.840.10045.4.3.2"
]
```

CSR attributes are configured with json file on registrar side. The following CSR that doesn't use `EC` key algorithm with `prime256v1` curve, or is not signed with `ecdsa-with-SHA256` signature algorithm **may fail**. More attributes may be added and updated here.

### Simple enrollment

Resource: `/.well-known/est/sen`, `CoAP POST`

The device uses a different key pair to create a `certificate-signing-request`(CSR). If the CSR is qualified, registrar will return a domain CA signed `operational certificate` of this CSR.

#### Response

The response is a `application/pkix-cert`message which includes only the signed domain operational certificate.

### Simple reenrollment

Resource: `/.well-known/est/sren`, `CoAP POST`

Almost the same as simple reenrollment.

### Request CA certificate

Resource: `/.well-known/est/cacerts`, `CoAP GET`

***Not Required by Thread, Not Implemented***.

## Commissioner API

### COM_TOK.req

Resource: `/.well-known/ccm`, `CoAP POST`

#### Establish DTLS connection

To establish a DTLS connection to the registrar, the commissioner should possess certificate signed by domain CA.

#### Protocol

The COM_TOK request/response protocol is derived from [draft-ietf-ace-oauth-authz-22](https://tools.ietf.org/html/draft-ietf-ace-oauth-authz-22).

#### Example payloads

- COM_TOK.req
  The content format of COM_TOK.req is `application/cwt(61)` and the payload is a serialized CBOR Map:

    ```text
    {
        3: "TestDomainTCE", // REQ_AUD = domain-name
        12: {
            1: {
                -3: h'77B892EEF7CA9575F53A2979F2AF9E23D30481DB05C9733E91E15981E3CFBB02',
                1: 2,
                -2: h'93D86471EC6D0C2EFA059D1AF8166306DDA6F0BC6C15FE92C0134B1C4F50F512',
                -1: 1
            }
        },              // REQ_CNF = COSE-KEY: public key
        24: "com-1",    // CLIENT_ID
        33: 2           // GRANT_TYPE = CLIENT_CREDENTIAL
    }
    ```

- COM_TOK.rsp
    The content format of COM_TOK.req is `application/cwt(61)` and the payload is a standard serialized CWT object:

    ```text
    # The cose-sign1 payload
    18([
        h'A10126',
        {},
        h'A4036D54657374446F6D61696E54434504781832
          3031392D30342D31325430343A30393A35372E38
          38305A01784204220420333F35EFBFBDEFBFBD36
          7FEFBFBDEFBFBD380933EFBFBD0B0121EFBFBDEF
          BFBD1CEFBFBDEFBFBDEFBFBDEFBFBD1B65EFBFBD
          101EEFBFBD34EFBFBDEFBFBD08A101F6',
        h'EFD620C7CA160AFA6EE0D299C60204B1669287E1
          E82CAC11EC3E2F0F40A0074D3BD23A5A72B07AE8
          F8A4ED2A742D37F9F382E594FE4364EC373D7ADC
          47A91E46'
    ])
    ```
