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

package com.google.openthread.pledge;

import COSE.CoseException;
import COSE.Message;
import COSE.MessageTag;
import COSE.OneKey;
import COSE.Sign1Message;
import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.ExtendedMediaTypeRegistry;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.californium.core.CoapClient;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP.ResponseCode;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Pledge extends CoapClient {
  static {
    BouncyCastleInitializer.init();
  }

  public enum CertState {
    NO_CONTACT,
    PROVISIONALLY_ACCEPT,
    ACCEPT
  }

  /**
   * Constructing pledge with credentials and uri of the registrar
   *
   * @param privateKey the manufacturer private key
   * @param certificateChain the manufacturer certificate chain leading to the masa and including
   *     masa certificate
   * @param hostURI uri of host (registrar)
   * @throws PledgeException
   */
  public Pledge(PrivateKey privateKey, X509Certificate[] certificateChain, String hostURI)
      throws PledgeException {
    super(hostURI);
    init(privateKey, certificateChain, hostURI);
  }

  public String getHostURI() {
    return hostURI;
  }

  public Pledge(PrivateKey privateKey, X509Certificate[] certificateChain, String host, int port)
      throws PledgeException {
    this(privateKey, certificateChain, host + ":" + port);
  }

  public static String getSerialNumber(X509Certificate idevid) {
    try {
      String serialNumber = SecurityUtils.getSerialNumber(idevid);
      if (serialNumber != null) {
        return serialNumber;
      }

      logger.info("extracting Serial-Number from certificate failed, trying HW-Serial-Number");

      // Base64 encoded to convert it to printable string
      return Base64.toBase64String(
          SecurityUtils.getHWModuleName(idevid).getSerialNumber().getOctets());
    } catch (CertificateEncodingException e) {
      logger.error("bad certificate: " + e.getMessage());
      e.printStackTrace();
      return null;
    }
  }

  public X509Certificate getOperationalCert() {
    return operationalCertificate;
  }

  // BRSKI protocol

  /**
   * Request constrained voucher from registrar.
   *
   * @return the constrained voucher
   * @throws IllegalStateException
   * @throws PledgeException
   */
  public ConstrainedVoucher requestVoucher() throws Exception {
    if (certState == CertState.ACCEPT) {
      throw new IllegalStateException("registrar certificate already accepted");
    }

    connect();
    if (!certVerifier.isPeerAccepted()) {
      throw new PledgeException("provisional DTLS connection failed");
    }
    certState = CertState.PROVISIONALLY_ACCEPT;
    registrarCertPath = certVerifier.getPeerCertPath();

    // 0. Build constrained voucher request
    ConstrainedVoucherRequest voucherRequest = new ConstrainedVoucherRequest();
    voucherRequest.assertion = Voucher.Assertion.PROXIMITY;
    voucherRequest.serialNumber = getSerialNumber(getCertificate());
    voucherRequest.nonce = generateNonce();

    // FIXME(wgtdkp): should use 'subjectPublicKeyInfo'
    voucherRequest.proximityRegistrarSPKI = getRegistrarCertificate().getPublicKey().getEncoded();
    if (!voucherRequest.validate()) {
      throw new PledgeException("validate voucher request failed");
    }

    return requestVoucher(voucherRequest);
  }

  /**
   * Request constrained voucher from registrar.
   *
   * @param req the voucher request
   * @return the constrained voucher
   * @throws IllegalStateException
   * @throws PledgeException
   */
  public ConstrainedVoucher requestVoucher(VoucherRequest req) throws PledgeException {
    // 0. Send to registrar
    CoapResponse response = sendRequestVoucher(req);

    // 1. Verify response
    if (response == null) {
      throw new PledgeException("voucher request failed: null response");
    }
    if (response.getCode() != ResponseCode.CHANGED) {
      throw new PledgeException("voucher request failed: " + response.getCode().toString());
    }

    if (response.getOptions().getContentFormat()
        != ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR) {
      throw new PledgeException(
          String.format(
              "expect voucher in format[%d], but got [%d]",
              ExtendedMediaTypeRegistry.APPLICATION_VOUCHER_COSE_CBOR,
              response.getOptions().getContentFormat()));
    }

    byte[] payload = response.getPayload();
    if (payload == null) {
      throw new PledgeException("unexpected null payload");
    }

    // 2. Receive voucher signed by MASA
    try {
      // 2.0 verify signature
      Sign1Message msg = (Sign1Message) Message.DecodeFromBytes(payload, MessageTag.Sign1);
      if (!msg.validate(new OneKey(getMASACertificate().getPublicKey(), null))) {
        throw new CoseException("COSE-sign1 voucher validation failed");
      }

      // 2.1 verify the voucher
      ConstrainedVoucher voucher =
          (ConstrainedVoucher) new CBORSerializer().deserialize(msg.GetContent());
      if (!voucher.validate()) {
        throw new PledgeException("voucher validation failed");
      }

      if (!voucher.serialNumber.equals(req.serialNumber)
          || !Arrays.equals(
              voucher.idevidIssuer, SecurityUtils.getAuthorityKeyId(getCertificate()))) {
        throw new PledgeException("serial number or idevid-issuer not matched");
      }
      if (req.nonce != null
          && (voucher.nonce == null || !Arrays.equals(req.nonce, voucher.nonce))) {
        throw new PledgeException("nonce not matched");
      }
      // TODO(wgtdkp): if nonce is not presented, make sure that the voucher is not expired

      if (voucher.pinnedDomainSPKI != null) {
        SubjectPublicKeyInfo spki = SubjectPublicKeyInfo.getInstance(voucher.pinnedDomainSPKI);
        X509EncodedKeySpec xspec = new X509EncodedKeySpec(spki.getEncoded());
        AlgorithmIdentifier keyAlg = spki.getAlgorithm();
        domainPublicKey =
            KeyFactory.getInstance(keyAlg.getAlgorithm().getId()).generatePublic(xspec);
      } else {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        Certificate domainCert =
            certFactory.generateCertificate(new ByteArrayInputStream(voucher.pinnedDomainCert));
        domainPublicKey = domainCert.getPublicKey();
      }
      if (!validateRegistrar(domainPublicKey)) {
        throw new PledgeException("validate registrar with pinned domain public key failed");
      }

      certState = CertState.ACCEPT;
      certVerifier.setDoVerification(true);

      // Add domain public key to trust anchors
      X500Principal issuer = getRegistrarCertificate().getIssuerX500Principal();
      certVerifier.addTrustAnchor(new TrustAnchor(issuer, domainPublicKey, null));

      return voucher;
    } catch (Exception e) {
      e.printStackTrace();
      throw new PledgeException("voucher error: " + e.getMessage());
    }
  }

  // EST protocol

  /**
   * Request CSR attributes before sending CSR.
   *
   * @throws IllegalStateException
   * @throws PledgeException
   */
  public void requestCSRAttributes() throws IllegalStateException, PledgeException {
    if (certState != CertState.ACCEPT) {
      throw new IllegalStateException("should successfully get voucher first");
    }

    CoapResponse response = sendRequestCSRAttributes();
    if (response == null) {
      throw new PledgeException("request CSR Attributes failed: null response");
    }
    if (response.getCode() != ResponseCode.CONTENT) {
      logger.warn("CSR attributes request failed: " + response.getCode().toString());
      return;
    }

    if (response.getOptions().getContentFormat()
        != ExtendedMediaTypeRegistry.APPLICATION_CSRATTRS) {
      logger.warn(
          "expect CSR attributes in format[%d], but got [%d]",
          ExtendedMediaTypeRegistry.APPLICATION_CSRATTRS, response.getOptions().getContentFormat());
      return;
    }

    byte[] payload = response.getPayload();
    if (payload == null) {
      throw new PledgeException("unexpected null payload");
    }

    try {
      // CBORObject cbor = CBORObject.DecodeFromBytes(payload);
      csrAttrs = CsrAttrs.getInstance(ASN1Primitive.fromByteArray(payload));
      if (csrAttrs.size() == 0) {
        throw new PledgeException("CSR Attributes response has no entry!");
      }
    } catch (Exception e) {
      logger.warn("bad CSR attributes response" + e.getMessage());
    }
  }

  // /.well-known/est/cacerts
  public void requestCACertificate() {
    // TODO(wgtdkp):
  }

  /**
   * The EST simpleEnrollment process.
   *
   * @throws Exception
   */
  public void enroll() throws Exception {
    if (certState != CertState.ACCEPT) {
      throw new IllegalStateException("should successfully get voucher first");
    }

    // TODO(wgtdkp): we should enable the certificate verifier now

    // 0. Generate operational keypair
    operationalKeyPair =
        SecurityUtils.genKeyPair(SecurityUtils.KEY_ALGORITHM, SecurityUtils.KEY_SIZE);

    PKCS10CertificationRequest csr =
        genCertificateRequest(
            SUBJECT_NAME,
            operationalKeyPair.getPublic(),
            SecurityUtils.SIGNATURE_ALGORITHM,
            operationalKeyPair.getPrivate());

    X509Certificate cert = requestSigning(csr, Constants.SIMPLE_ENROLL);
    if (cert == null) {
      throw new PledgeException("CSR response includes no certificate");
    }

    cert.verify(domainPublicKey);

    String subjectName = cert.getSubjectX500Principal().getName();
    logger.info("get operational certificate: " + subjectName);

    operationalCertificate = cert;
  }

  /**
   * The EST simpleReenrollment.
   *
   * @throws Exception
   */
  public void reenroll() throws Exception {
    if (certState != CertState.ACCEPT) {
      throw new IllegalStateException("should successfully get voucher first");
    }

    if (operationalCertificate == null || domainPublicKey == null) {
      throw new IllegalStateException("should enroll first");
    }

    // Reset the endpoint, so the pledge will rehandshake
    initEndpoint(privateKey, certificateChain, certVerifier);

    PKCS10CertificationRequest csr =
        genCertificateRequest(
            SUBJECT_NAME,
            operationalKeyPair.getPublic(),
            SecurityUtils.SIGNATURE_ALGORITHM,
            operationalKeyPair.getPrivate());

    X509Certificate cert = requestSigning(csr, Constants.SIMPLE_REENROLL);
    if (cert == null) {
      throw new PledgeException("CSR response includes no certificate");
    }

    cert.verify(domainPublicKey);

    String subjectName = cert.getSubjectX500Principal().getName();
    logger.info("renew operational certificate: " + subjectName);

    operationalCertificate = cert;
  }

  public CoapResponse sayHello() {
    setURI(getESTPath() + "/" + Constants.HELLO);
    return get();
  }

  public void reset() throws PledgeException {
    shutdown();
    init(privateKey, certificateChain, hostURI);
    initEndpoint(privateKey, certificateChain, certVerifier);
  }

  X509Certificate getCertificate() {
    return certificateChain[0];
  }

  X509Certificate getMASACertificate() {
    return certificateChain[certificateChain.length - 1];
  }

  private void init(PrivateKey privateKey, X509Certificate[] certificateChain, String hostURI)
      throws PledgeException {
    this.hostURI = hostURI;

    if (certificateChain.length < 2) {
      throw new PledgeException("bad certificate");
    }

    this.privateKey = privateKey;
    this.certificateChain = certificateChain;

    this.trustAnchors = new HashSet<>();
    this.trustAnchors.add(new TrustAnchor(getMASACertificate(), null));

    this.certVerifier = new PledgeCertificateVerifier(this.trustAnchors);

    registrarCertPath = null;
    domainPublicKey = null;
    operationalKeyPair = null;
    operationalCertificate = null;
    certState = CertState.NO_CONTACT;
    csrAttrs = null;

    initEndpoint(this.privateKey, this.certificateChain, this.certVerifier);
  }

  private CoapResponse sendRequestVoucher(VoucherRequest voucherRequest) {
    setURI(getESTPath() + "/" + Constants.REQUEST_VOUCHER);
    byte[] payload = new CBORSerializer().serialize(voucherRequest);
    return post(payload, ExtendedMediaTypeRegistry.APPLICATION_CBOR);
  }

  private CoapResponse sendRequestCSRAttributes() {
    setURI(getESTPath() + "/" + Constants.CSR_ATTRIBUTES);
    return get();
  }

  private CoapResponse sendCSR(PKCS10CertificationRequest csr, String resource) throws IOException {
    setURI(getESTPath() + "/" + resource);
    return post(csr.getEncoded(), ExtendedMediaTypeRegistry.APPLICATION_PKCS10);
  }

  private X509Certificate requestSigning(PKCS10CertificationRequest csr, String resource)
      throws Exception {
    // 0. Send CSR request and get response
    CoapResponse response = sendCSR(csr, resource);
    if (response == null) {
      throw new PledgeException("CSR request failed: null response");
    }
    if (response.getCode() != ResponseCode.CHANGED) {
      throw new PledgeException("CSR request failed: " + response.getCode().toString());
    }

    if (response.getOptions().getContentFormat()
        != ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT) {
      throw new PledgeException(
          String.format(
              "expect CSR response in format[%d], but got [%d]",
              ExtendedMediaTypeRegistry.APPLICATION_PKIX_CERT,
              response.getOptions().getContentFormat()));
    }

    byte[] payload = response.getPayload();
    if (payload == null) {
      throw new PledgeException("unexpected null payload");
    }

    // 1. Decode PKCS7 message in CBOR byte string
    // CBORObject cbor = CBORObject.DecodeFromBytes(payload);
    // CMSSignedData data = new CMSSignedData(cbor.GetByteString());
    // return extractCertFromCMSSignedData(data);
    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
    return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(payload));
  }

  private PKCS10CertificationRequest genCertificateRequest(
      String name, PublicKey publicKey, String signatureAlgorithm, PrivateKey signingPrivateKey)
      throws OperatorCreationException, PKCSException, GeneralSecurityException {
    X500Name subject = new X500Name(name);
    ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(signingPrivateKey);
    PKCS10CertificationRequest csr =
        new JcaPKCS10CertificationRequestBuilder(subject, publicKey).build(signer);
    ContentVerifierProvider verifier = new JcaContentVerifierProviderBuilder().build(publicKey);
    if (!csr.isSignatureValid(verifier)) {
      throw new GeneralSecurityException("signature verification failed");
    }
    return csr;
  }

  private X509Certificate extractCertFromCMSSignedData(CMSSignedData signedData)
      throws CertificateException {
    Store<X509CertificateHolder> certStore = signedData.getCertificates();
    for (X509CertificateHolder holder : certStore.getMatches(null)) {
      return new JcaX509CertificateConverter().getCertificate(holder);
    }
    return null;
  }

  // Generate 64-bit cryptographically strong random/pseudo-random number
  public static byte[] generateNonce() {
    SecureRandom random = new SecureRandom();

    // FIXME(wgtdkp): geneateSeed() will hang on GCE VM.
    random = new SecureRandom(random.generateSeed(20));
    byte[] nonce = new byte[8];
    random.nextBytes(nonce);
    return nonce;
  }

  private void initEndpoint(
      PrivateKey privateKey, X509Certificate[] certificateChain, CertificateVerifier verifier) {
    CoapEndpoint endpoint =
        SecurityUtils.genCoapClientEndPoint(
            new X509Certificate[] {}, privateKey, certificateChain, verifier);
    setEndpoint(endpoint);
  }

  // We need a provisional DTLS session before requesting
  // voucher since we need registrar certificate. But there
  // is no 'connect' API to build this session ahead. We
  // here send a GET to registrar to have this session built.
  private void connect() {
    setURI(getESTPath());
    ping();
  }

  private boolean validateRegistrar(PublicKey domainPublicKey) {
    try {
      List<? extends Certificate> certs = registrarCertPath.getCertificates();
      X509Certificate lastCert = (X509Certificate) certs.get(certs.size() - 1);

      Set<TrustAnchor> trustAnchors = new HashSet<>();

      // Build trust anchor with the last certificate's issuer name and public key of Domain CA.
      trustAnchors.add(new TrustAnchor(lastCert.getIssuerX500Principal(), domainPublicKey, null));
      PKIXParameters params = new PKIXParameters(trustAnchors);

      params.setRevocationEnabled(false);
      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(registrarCertPath, params);
      return true;
    } catch (GeneralSecurityException e) {
      logger.error("Certificate validation failed: " + e.getMessage());
      return false;
    }
  }

  private X509Certificate getRegistrarCertificate() {
    return (X509Certificate) registrarCertPath.getCertificates().get(0);
  }

  private String getESTPath() {
    return hostURI + Constants.EST_PATH;
  }

  private static final String SUBJECT_NAME = "C=CN,L=SH,O=GG,OU=OpenThread,CN=pledge_op";

  private String hostURI;
  private PrivateKey privateKey;
  private X509Certificate[] certificateChain;

  private Set<TrustAnchor> trustAnchors;
  PledgeCertificateVerifier certVerifier;

  private CertPath registrarCertPath;

  private PublicKey domainPublicKey;

  private KeyPair operationalKeyPair;
  private X509Certificate operationalCertificate;

  private CertState certState = CertState.NO_CONTACT;

  private CsrAttrs csrAttrs;

  private static Logger logger = LoggerFactory.getLogger(Pledge.class);
}
