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

package com.google.openthread.registrar;

import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.ExtendedMediaTypeRegistry;
import com.google.openthread.RequestDumper;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.ConstrainedVoucherRequest;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.pledge.Pledge;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.*;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResource;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.CoapServer;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.core.server.resources.CoapExchange;
import org.eclipse.californium.elements.auth.X509CertPath;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The registrar implements BRSKI-EST over CoAPs
 *
 * @author wgtdkp
 */
public class Registrar extends CoapServer {
  // EST resources
  //      EST                 EST-CoAP
  //      /cacerts            /cacerts
  //      /simpleenroll       /sen
  //      /simplereenroll     /sren
  //      /fullcmc
  //      /serverkeygen       /skg
  //      /csrattrs           /att

  // Voucher related
  //      BRSKI               EST-coaps       resource type
  //      /requestvoucher     /rv             ace.rt.rv
  //      /voucher-status     /vs             ace.rt.vs
  //      /enrollstatus       /es             ace.rt.es
  //      /requestauditlog    /ra             ace.rt.ra

  static {
    BouncyCastleInitializer.init();
  }

  // FIXME(wgtdkp): this is just hard coded walkaroud for pledges that include
  // no masa uri in its manufacturer device certificate. We should config this
  // in command line or config file
  public static final String DEFAULT_MASA_URI = "coaps://[::1]:5685";

  /**
   * Constructing registrar with credentials and listening port.
   *
   * @param masaTrustAnchors pre-installed MASA trust anchors
   * @param privateKey the private key used for DTLS connection
   * @param certificateChain the certificate chain leading up to domain CA and including domain CA
   *     certificate
   * @param port the port to listen on
   * @throws RegistrarException
   */
  Registrar(
      PrivateKey privateKey,
      X509Certificate[] certificateChain,
      X509Certificate[] masaTrustAnchors,
      int port)
      throws RegistrarException {
    if (certificateChain.length < 2) {
      throw new RegistrarException("bad certificate chain");
    }

    this.listenPort = port;
    this.privateKey = privateKey;
    this.certificateChain = certificateChain;
    this.masaTrustAnchors = masaTrustAnchors;
    try {
      this.csrAttributes = new CSRAttributes(CSRAttributes.DEFAULT_FILE);
    } catch (Exception e) {
      throw new RegistrarException(e.getMessage());
    }

    initResources();

    initEndpoint();
  }

  public void setDomainCA(DomainCA domainCA) {
    this.domainCA = domainCA;
  }

  public int getListenPort() {
    return listenPort;
  }

  public String getDomainName() {
    // It is the caller's responsibility to check if domainCA is null.
    return domainCA.getDomainName();
  }

  public final class VoucherRequestResource extends CoapResource {
    public VoucherRequestResource() {
      super(Constants.REQUEST_VOUCHER);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      int contentFormat = exchange.getRequestOptions().getContentFormat();

      try {
        if (contentFormat == ExtendedMediaTypeRegistry.APPLICATION_CBOR) {
          RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

          // Validate pledge's voucher request
          ConstrainedVoucherRequest pledgeReq =
              (ConstrainedVoucherRequest)
                  new CBORSerializer().deserialize(exchange.getRequestPayload());
          if (!pledgeReq.validate()) {
            logger.error("bad voucher request");
            exchange.respond(ResponseCode.UNPROCESSABLE_ENTITY);
            return;
          }

          // Get client certificate, it is pledge's idevid for voucher request
          Principal clientId =
              exchange.advanced().getRequest().getSourceContext().getPeerIdentity();
          if (!(clientId instanceof X509CertPath)) {
            logger.error("unsupported client identity");
            exchange.respond(ResponseCode.UNPROCESSABLE_ENTITY);
            return;
          }
          X509Certificate idevid = ((X509CertPath) clientId).getTarget();

          // Constructing new voucher request for MASA
          // ref: section 5.5 BRSKI
          ConstrainedVoucherRequest req = new ConstrainedVoucherRequest();
          req.assertion = pledgeReq.assertion;

          // Optional, but mandatory for Thread 1.2
          req.nonce = pledgeReq.nonce;

          // Optional, could be null.
          if (pledgeReq.proximityRegistrarSPKI != null) {
            if (!Arrays.equals(
                pledgeReq.proximityRegistrarSPKI, getCertificate().getPublicKey().getEncoded())) {
              logger.error("unmatched proximity registrar SPKI");
              exchange.respond(ResponseCode.BAD_REQUEST);
              return;
            }
          }

          req.proximityRegistrarSPKI = pledgeReq.proximityRegistrarSPKI;

          // Optional
          req.createdOn = new Date();

          // serialNumber provided by pledge's voucher request must match the one
          // extracted from pledge's idevid.
          req.serialNumber = Pledge.getSerialNumber(idevid);
          if (req.serialNumber == null || !req.serialNumber.equals(pledgeReq.serialNumber)) {
            logger.error(
                String.format(
                    "bad serial number in voucher request: [%s] != [%s]",
                    pledgeReq.serialNumber, req.serialNumber));
            exchange.respond(ResponseCode.UNPROCESSABLE_ENTITY);
            return;
          }

          // Optional, could be null. Settting idevid-issuer as
          // authority key identifier of pledge certificate.
          // But not optional for OpenThread.
          req.idevidIssuer = SecurityUtils.getAuthorityKeyId(idevid);
          if (req.idevidIssuer != null) {
            logger.info(
                String.format(
                    "idevid-issuer in voucher request [len=%d, %s]",
                    req.idevidIssuer.length, Hex.toHexString(req.idevidIssuer)));
          } else {
            logger.error("missing idevid-issuer in voucher request");
          }

          // prior-signed-voucher-request for COSE-signed voucher request

          // Create CMS-cbor voucher request
          byte[] content = new CBORSerializer().serialize(req);
          byte[] payload;
          try {
            payload =
                SecurityUtils.genCMSSignedMessage(
                    privateKey,
                    getCertificate(),
                    SecurityUtils.SIGNATURE_ALGORITHM,
                    certificateChain,
                    content);
          } catch (Exception e) {
            logger.warn("CMS signing voucher request failed: " + e.getMessage());
            e.printStackTrace();
            exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
            return;
          }

          // Request voucher from MASA server
          String uri = SecurityUtils.getMasaUri(idevid);
          if (uri == null) {
            logger.warn(
                "pledge certificate does not include MASA uri, using default masa uri: "
                    + DEFAULT_MASA_URI);
            uri = DEFAULT_MASA_URI;
          }

          MASAConnector masaClient = new MASAConnector(masaTrustAnchors);
          CoapResponse response = masaClient.requestVoucher(payload, uri);

          if (response == null || response.getCode() != ResponseCode.CHANGED) {
            logger.warn("request voucher from MASA failed");
            exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
            return;
          }

          if (response.getOptions().getContentFormat()
              != ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR) {
            // TODO(wgtdkp): we can support more formats
            logger.error(
                "Not supported content format: " + response.getOptions().getContentFormat());
            exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
            return;
          }

          if (response.getPayload() == null) {
            logger.warn("unexpected null payload from MASA server");
            exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
            return;
          }

          // Registrar forwards MASA's response without modification
          exchange.respond(
              response.getCode(),
              response.getPayload(),
              ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR);
        } else {
          // TODO(wgtdkp): handle a singed voucher request
          logger.error("unsupported voucher request format: " + contentFormat);
          exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
        }
      } catch (Exception e) {
        logger.warn("handle voucher request failed: " + e.getMessage());
        e.printStackTrace();
        exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
        return;
      }
    }
  }

  public final class MASAConnector extends CoapClient {

    MASAConnector(X509Certificate[] trustAnchors) {
      initEndPoint(trustAnchors);
    }

    /**
     * Forwarding voucher to masa
     *
     * @param payload
     * @param masaURI
     * @return null if any error happens
     */
    public CoapResponse requestVoucher(byte[] payload, String masaURI) {
      setURI(masaURI + Constants.EST_PATH + "/" + Constants.REQUEST_VOUCHER);
      return post(payload, ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_CMS_CBOR);
    }

    private void initEndPoint(X509Certificate[] trustAnchors) {
      CoapEndpoint endpoint =
          SecurityUtils.genCoapClientEndPoint(trustAnchors, privateKey, certificateChain);
      setEndpoint(endpoint);
    }
  }

  public class EnrollResource extends CoapResource {
    public EnrollResource() {
      this(Constants.SIMPLE_ENROLL);
    }

    protected EnrollResource(String name) {
      super(name);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      int contentFormat = exchange.getRequestOptions().getContentFormat();
      if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_PKCS10) {
        exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
        return;
      }

      try {
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        byte[] payload = exchange.getRequestPayload();

        PKCS10CertificationRequest csr = new PKCS10CertificationRequest(payload);
        X509Certificate cert = domainCA.signCertificate(csr);

        exchange.respond(
            ResponseCode.CHANGED,
            cert.getEncoded(),
            ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT);
      } catch (Exception e) {
        logger.warn("sign certificate failed: " + e.getMessage());
        e.printStackTrace();
        // TODO(wgtdkp):
        exchange.respond(ResponseCode.SERVICE_UNAVAILABLE);
        return;
      }
    }
  }

  public final class ReenrollResource extends EnrollResource {
    public ReenrollResource() {
      super(Constants.SIMPLE_REENROLL);
    }
  }

  public final class CsrAttrsResource extends CoapResource {
    public CsrAttrsResource() {
      super(Constants.CSR_ATTRIBUTES);
    }

    @Override
    public void handleGET(CoapExchange exchange) {
      try {
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        CsrAttrs csrAttrs = getCsrAttrs();

        // No base64 encoding
        exchange.respond(
            ResponseCode.CONTENT,
            csrAttrs.getEncoded(),
            ExtendedMediaTypeRegistry.APPLICATION_CSRATTRS);
      } catch (IOException e) {
        logger.warn("CSR attribute request failed: " + e.getMessage());
        exchange.respond(ResponseCode.BAD_REQUEST);
      }
    }

    private CsrAttrs getCsrAttrs() {
      return new CsrAttrs(csrAttributes.getAttrAndOids());
    }
  }

  public final class CommissionerTokenResource extends CoapResource {
    public CommissionerTokenResource() {
      super(Constants.COM_TOK);
    }

    @Override
    public void handlePOST(CoapExchange exchange) {
      int contentFormat = exchange.getRequestOptions().getContentFormat();
      if (contentFormat != ExtendedMediaTypeRegistry.APPLICATION_CWT) {
        exchange.respond(ResponseCode.UNSUPPORTED_CONTENT_FORMAT);
        return;
      }

      try {
        RequestDumper.dump(logger, getURI(), exchange.getRequestPayload());

        // TODO(wgtdkp): verify the COM_TOK.req
        CBORObject req = CBORObject.DecodeFromBytes(exchange.getRequestPayload());
        validateComTokenReq(req);

        CBORObject signedToken = domainCA.signCommissionerToken(req);
        byte[] encodedToken = signedToken.EncodeToBytes();
        logger.info(
            "response token[len={}] : {}", encodedToken.length, Hex.toHexString(encodedToken));

        exchange.respond(
            ResponseCode.CHANGED, encodedToken, ExtendedMediaTypeRegistry.APPLICATION_COSE_SIGN1);
      } catch (Exception e) {
        logger.warn("commissioner token request failed: " + e.getMessage());
        e.printStackTrace();
        exchange.respond(ResponseCode.BAD_REQUEST, e.getMessage());
      }
    }
  }

  public static void validateComTokenReq(CBORObject req) throws RegistrarException {
    CBORObject grantType = req.get(CBORObject.FromObject(se.sics.ace.Constants.GRANT_TYPE));
    if (grantType == null) {
      throw new RegistrarException("missing grant-type");
    } else if (grantType.AsInt32() != se.sics.ace.Constants.GT_CLI_CRED) {
      throw new RegistrarException("COM_TOK.req grant-type is wrong: " + grantType.AsInt32());
    }

    CBORObject clientId = req.get(CBORObject.FromObject(se.sics.ace.Constants.CLIENT_ID));
    if (clientId == null) {
      throw new RegistrarException("missing client-id");
    }

    CBORObject reqAud = req.get(CBORObject.FromObject(se.sics.ace.Constants.AUD));
    if (reqAud == null) {
      throw new RegistrarException("missing req-aud");
    }

    CBORObject reqCnf = req.get(CBORObject.FromObject(se.sics.ace.Constants.REQ_CNF));
    if (reqCnf == null) {
      throw new RegistrarException("missing req-cnf");
    }

    CBORObject coseKey = reqCnf.get(CBORObject.FromObject(se.sics.ace.Constants.COSE_KEY));
    if (coseKey == null) {
      throw new RegistrarException("missing cose-key in req-cnf");
    }
  }

  X509Certificate getCertificate() {
    return certificateChain[0];
  }

  X509Certificate getDomainCertificate() {
    return certificateChain[certificateChain.length - 1];
  }

  private void initResources() {
    CoapResource wellKnown = new CoapResource(".well-known");
    CoapResource est = new CoapResource("est");
    VoucherRequestResource rv = new VoucherRequestResource();
    CsrAttrsResource att = new CsrAttrsResource();
    EnrollResource enroll = new EnrollResource();
    ReenrollResource reenroll = new ReenrollResource();

    // EST resources
    est.add(enroll);
    est.add(reenroll);
    est.add(rv);
    est.add(att);
    wellKnown.add(est);
    this.add(wellKnown);

    est.add(
        new CoapResource(Constants.HELLO) {
          @Override
          public void handleGET(CoapExchange exchange) {
            exchange.respond(ResponseCode.CONTENT, "hello CoAP");
          }
        });

    // Commissioning
    wellKnown.add(new CommissionerTokenResource());
  }

  private void initEndpoint() {
    List<X509Certificate> trustAnchors = new ArrayList<>(Arrays.asList(masaTrustAnchors));
    trustAnchors.add(getDomainCertificate());

    CoapEndpoint endpoint =
        SecurityUtils.genCoapServerEndPoint(
            listenPort,
            trustAnchors.toArray(new X509Certificate[trustAnchors.size()]),
            privateKey,
            certificateChain,
            new RegistrarCertificateVerifier(
                trustAnchors.toArray(new X509Certificate[trustAnchors.size()])));
    addEndpoint(endpoint);
  }

  private final int listenPort;

  private DomainCA domainCA;

  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;

  private X509Certificate[] masaTrustAnchors;

  private CSRAttributes csrAttributes;

  private static Logger logger = LoggerFactory.getLogger(Registrar.class);
}
