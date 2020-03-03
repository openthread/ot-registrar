/*
 *    Copyright (c) 2019, The OpenThread Registrar Authors.
 *    All rights reserved.
 *
 *    Redistribution and use in source and binary forms, with or without
 *    modification, are permitted provided that the following conditions are met:
 *    1. Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of the copyright holder nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *    AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *    ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 *    LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 *    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 *    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 *    POSSIBILITY OF SUCH DAMAGE.
 */

package com.google.openthread.commissioner;

import COSE.CoseException;
import COSE.OneKey;
import com.google.openthread.Constants;
import com.google.openthread.ExtendedMediaTypeRegistry;
import com.google.openthread.SecurityUtils;
import com.upokecenter.cbor.CBORObject;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.eclipse.californium.core.network.CoapEndpoint;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

public class Commissioner extends CoapClient {

  /**
   * Constructing commissioner with credentials
   *
   * @param privateKey the private key used for (D)TLS connection
   * @param certificateChain the certificate chain leading up to domain and including domain
   *     certificate
   * @throws CommissionerException
   */
  public Commissioner(PrivateKey privateKey, X509Certificate[] certificateChain)
      throws CommissionerException {
    if (certificateChain.length < 2) {
      throw new CommissionerException("bad certificate chain");
    }

    // TODO(wgtdkp): verify public and private key are match
    this.privateKey = privateKey;
    this.certificateChain = certificateChain;

    this.certVerifier = new CommissionerCertificateVerifier(getDomainCertificate());

    initEndpoint();
  }

  public CWT requestToken(String domainName, String registrarURI) throws CommissionerException {
    // 0. build COM_TOK.req
    CBORObject req = genTokenRequest(domainName, getCertificate().getPublicKey());

    // 1. send COM_TOK.req & receive COM_TOK.rsp
    CoapResponse response = sendTokenRequest(req, registrarURI);
    if (response.getCode() != CoAP.ResponseCode.CHANGED) {
      throw new CommissionerException("request token failed: " + response.getCode());
    }

    if (response.getOptions().getContentFormat()
        != ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1) {
      throw new CommissionerException(
          String.format(
              "expect COM_TOK in format[%d], but got [%d]",
              ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1,
              response.getOptions().getContentFormat()));
    }

    // 2. verify
    byte[] rawToken = response.getPayload();
    if (rawToken == null) {
      throw new CommissionerException("unexpected null payload");
    }

    CWT comTok;
    try {
      comTok = verifyToken(rawToken);
    } catch (Exception e) {
      throw new CommissionerException("COM_TOK verification failed: " + e.getMessage());
    }

    CBORObject aud = comTok.getClaim(se.sics.ace.Constants.AUD);
    if (!aud.AsString().equals(domainName)) {
      throw new CommissionerException("COM_TOK domain names not match");
    }
    // TODO(wgtdkp): extract and verify other claims

    return comTok;
  }

  public static CBORObject genTokenRequest(String domainName, PublicKey publicKey)
      throws CommissionerException {
    CBORObject req = CBORObject.NewMap();
    req.Add(se.sics.ace.Constants.GRANT_TYPE, se.sics.ace.Constants.GT_CLI_CRED);
    req.Add(se.sics.ace.Constants.CLIENT_ID, "com-" + allocateClientId().toString());
    req.Add(se.sics.ace.Constants.AUD, domainName);

    // TODO(wgtdkp): support truncated subject key id
    // req.Add(se.sics.ace.Constants.REQ_CNF, getTruncatedSubjectKeyId(16));

    CBORObject cnf = CBORObject.NewMap();
    try {
      cnf.Add(se.sics.ace.Constants.COSE_KEY, new OneKey(publicKey, null).AsCBOR());
    } catch (CoseException e) {
      throw new CommissionerException("public key error: " + e.getMessage());
    }

    req.Add(se.sics.ace.Constants.REQ_CNF, cnf);
    return req;
  }

  public CoapResponse sendTokenRequest(CBORObject req, String registrarURI) {
    setURI(registrarURI + Constants.CCM_PATH);
    return post(req.EncodeToBytes(), ExtendedMediaTypeRegistry.APPLICATION_CWT);
  }

  public CWT verifyToken(byte[] rawToken) throws Exception {
    PublicKey publicKey = getDomainCertificate().getPublicKey();
    OneKey pubKey = new OneKey(publicKey, null);
    CwtCryptoCtx ctx = CwtCryptoCtx.sign1Verify(pubKey, null);
    return CWT.processCOSE(rawToken, ctx);
  }

  // TODO(wgtdkp): Use X509ExtensionUtils.truncatedSubjectKeyId
  /*
  public byte[] getTruncatedSubjectKeyId(int length) throws CommissionerException {
      byte[] keyId = getCertificate().getExtensionValue("2.5.29.14");
      if (keyId.length < length) {
          throw new CommissionerException("subject key identifier is shorter than " + length);
      }
      return Arrays.copyOf(keyId, length);
  }
  */

  public static synchronized BigInteger allocateClientId() {
    clientId = clientId.add(BigInteger.ONE);
    return clientId;
  }

  X509Certificate getCertificate() {
    return certificateChain[0];
  }

  X509Certificate getDomainCertificate() {
    return certificateChain[certificateChain.length - 1];
  }

  private void initEndpoint() {
    CoapEndpoint endpoint =
        SecurityUtils.genCoapClientEndPoint(
            new X509Certificate[] {}, privateKey, certificateChain, certVerifier);
    setEndpoint(endpoint);
  }

  private static BigInteger clientId = BigInteger.ZERO;

  private PrivateKey privateKey;

  private X509Certificate[] certificateChain;

  private CommissionerCertificateVerifier certVerifier;
}
