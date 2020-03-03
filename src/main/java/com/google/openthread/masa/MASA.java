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

package com.google.openthread.masa;

import COSE.CoseException;
import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.ExtendedMediaTypeRegistry;
import com.google.openthread.RequestDumper;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.ConstrainedVoucher;
import com.google.openthread.brski.ConstrainedVoucherRequest;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MASA extends CoapServer {
  static {
    BouncyCastleInitializer.init();
  }

  public MASA(PrivateKey privateKey, X509Certificate certificate, int port) {
    this.privateKey = privateKey;
    this.certificate = certificate;

    this.listenPort = port;

    initResources();

    initEndPoint();
  }

  public int getListenPort() {
    return listenPort;
  }

  X509Certificate getCertificate() {
    return certificate;
  }

  final class VoucherRequestResource extends CoapResource {
    VoucherRequestResource() {
      super(Constants.REQUEST_VOUCHER);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      int contentFormat = exchange.getRequestOptions().getContentFormat();
      if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_CBOR) {
        // TODO(wgtdkp): support more formats
        exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
        return;
      }

      RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

      byte[] reqContent;
      List<X509Certificate> reqCerts = new ArrayList<>();
      try {
        reqContent = SecurityUtils.decodeCMSSignedMessage(exchange.getRequestPayload(), reqCerts);
      } catch (Exception e) {
        logger.error("CMS signed voucher request error: " + e.getMessage());
        e.printStackTrace();
        exchange.respond(ResponseCode.FORBIDDEN);
        return;
      }

      ConstrainedVoucherRequest req =
          (ConstrainedVoucherRequest) new CBORSerializer().deserialize(reqContent);
      if (!req.validate() || reqCerts.isEmpty()) {
        logger.error("invalid voucher request");
        exchange.respond(ResponseCode.BAD_REQUEST);
        return;
      }

      // TODO(wgtdkp):
      // Section 5.5.1 BRSKI: MASA renewal of expired vouchers

      // TODO(wgtdkp):
      // Section 5.5.2 BRSKI: MASA verification of voucher-request signature consistency

      // TODO(wgtdkp):
      // Section 5.5.3 BRSKI: MASA authentication of registrar (certificate)

      // TODO(wgtdkp):
      // Section 5.5.4 BRSKI: MASA revocation checking of registrar (certificate)

      // TODO(wgtdkp):
      // Section 5.5.5 BRSKI: MASA verification of pledge prior-signed-voucher-request

      // TODO(wgtdkp):
      // Section 5.5.6 BRSKI: MASA pinning of registrar

      // TODO(wgtdkp):
      // Section 5.5.7 BRSKI: MASA nonce handling

      // Section 5.6 BRSKI: MASA and Registrar Voucher Response

      ConstrainedVoucher voucher = new ConstrainedVoucher();

      voucher.createdOn = new Date();

      voucher.nonce = req.nonce;

      // FIXME(wgtdkp): not standard
      voucher.assertion = req.assertion;

      voucher.idevidIssuer = req.idevidIssuer;
      voucher.serialNumber = req.serialNumber;
      voucher.domainCertRevocationChecks = false;

      try {
        X509Certificate domainCert = reqCerts.get(reqCerts.size() - 1);
        // SubjectPublicKeyInfo spki =
        // SubjectPublicKeyInfo.getInstance(domainCert.getPublicKey().getEncoded());
        // voucher.pinnedDomainSPKI = spki.getEncoded();

        // According to BHC-405: use Domain CA Certificate in voucher response
        voucher.pinnedDomainCert = domainCert.getEncoded();
      } catch (Exception e) {
        // logger.error("get encoded subject-public-key-info failed: " + e.getMessage());
        logger.error("get encoded domain-ca-cert failed: " + e.getMessage());
        e.printStackTrace();
        exchange.respond(ResponseCode.SERVICE_UNAVAILABLE, e.getMessage());
        return;
      }

      if (voucher.nonce == null) {
        // The voucher is going to expire in 10 minutes
        voucher.expiresOn = new Date(System.currentTimeMillis() + 1000 * 60 * 10);
      }

      // TODO(wgtdkp): update audit log

      // Generate and send response
      try {
        byte[] content = new CBORSerializer().serialize(voucher);
        byte[] payload =
            SecurityUtils.genCoseSign1Message(
                privateKey, SecurityUtils.COSE_SIGNATURE_ALGORITHM, content);
        exchange.respond(
            ResponseCode.CHANGED, payload, ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR);
      } catch (CoseException e) {
        logger.error("COSE signing voucher request failed: " + e.getMessage());
        exchange.respond(ResponseCode.NOT_ACCEPTABLE);
      }
    }
  }

  private void initResources() {
    CoapResource wellknown = new CoapResource(".well-known");
    CoapResource est = new CoapResource("est");
    VoucherRequestResource rv = new VoucherRequestResource();

    est.add(rv);
    wellknown.add(est);
    this.add(wellknown);
  }

  private void initEndPoint() {
    X509Certificate[] certificateChain = new X509Certificate[] {certificate};

    // We currently don't authenticate a client
    CertificateVerifier verifier = new SecurityUtils.DoNothingVerifier(certificateChain);
    CoapEndpoint endpoint =
        SecurityUtils.genCoapServerEndPoint(
            listenPort,
            new X509Certificate[] {certificate},
            privateKey,
            certificateChain,
            verifier);
    addEndpoint(endpoint);
  }

  private final int listenPort;

  private final PrivateKey privateKey;

  private final X509Certificate certificate;

  private static final Logger logger = LoggerFactory.getLogger(MASA.class);
}
