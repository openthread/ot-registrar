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

package com.google.openthread.domainca;

import COSE.OneKey;
import com.google.openthread.BouncyCastleInitializer;
import com.google.openthread.Constants;
import com.google.openthread.SecurityUtils;
import com.google.openthread.brski.Voucher;
import com.upokecenter.cbor.CBORObject;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import se.sics.ace.cwt.CWT;
import se.sics.ace.cwt.CwtCryptoCtx;

public class DomainCA {
  static {
    BouncyCastleInitializer.init();
  }

  public DomainCA(String domainName, PrivateKey privatekey, X509Certificate certificate) {
    this.domainName = domainName;
    this.privateKey = privatekey;
    this.certificate = certificate;
  }

  public PublicKey getPublicKey() {
    return getCertificate().getPublicKey();
  }

  public X509Certificate getCertificate() {
    return certificate;
  }

  // TODO(wgtdkp): should read from certificate's subject alt name
  public String getDomainName() {
    return domainName;
  }

  public X509Certificate signCertificate(PKCS10CertificationRequest csr) throws Exception {

    // 0. POP (proof-of-possession) verification
    // Ref: RFC-7030 [3.4]
    if (!csr.isSignatureValid(
        new JcaContentVerifierProviderBuilder().build(csr.getSubjectPublicKeyInfo()))) {
      throw new GeneralSecurityException("POP verification failed");
    }

    // TODO(wgtdkp): validate CSR request

    // 1. Build certificate
    X500Name issuer = getSubjectName();
    BigInteger serial = allocateSerialNumber();
    Date notBefore = new Date();
    Date notAfter =
        new Date(System.currentTimeMillis() + Constants.CERT_VALIDITY * 3600 * 24 * 1000);
    X509v3CertificateBuilder builder =
        new X509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, csr.getSubject(), csr.getSubjectPublicKeyInfo());

    logger.info("operational certificate not-before: " + notBefore.toString());
    logger.info("operational certificate not-after: " + notAfter.toString());

    // As defined in 4.2.1.2 of RFC 5280, authority key identifier (subject key identifier of CA)
    // must be calculated by SHA1.
    X509ExtensionUtils extUtils = new BcX509ExtensionUtils();
    builder.addExtension(Extension.basicConstraints, false, new BasicConstraints(false));

    SubjectKeyIdentifier subjectKeyId =
        extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo());
    builder.addExtension(Extension.subjectKeyIdentifier, false, subjectKeyId);

    // Or we should directly copy this from subject-key-identifier of domain CA ?
    AuthorityKeyIdentifier authorityKeyId =
        extUtils.createAuthorityKeyIdentifier(
            SubjectPublicKeyInfo.getInstance(getPublicKey().getEncoded()));
    builder.addExtension(Extension.authorityKeyIdentifier, false, authorityKeyId);

    // Includes domain name in subfield of SubjectAltName extension
    GeneralNames subjectAltName =
        new GeneralNames(new GeneralName(GeneralName.dNSName, domainName));
    builder.addExtension(Extension.subjectAlternativeName, false, subjectAltName);

    // 2. Sign and verify certificate
    ContentSigner signer =
        new JcaContentSignerBuilder(SecurityUtils.SIGNATURE_ALGORITHM).build(this.privateKey);
    X509CertificateHolder holder = builder.build(signer);
    X509Certificate cert = new JcaX509CertificateConverter().getCertificate(holder);
    cert.verify(this.certificate.getPublicKey());

    // 3. Make sure the signed certificate is validate
    {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      List<X509Certificate> certs = new ArrayList<>();
      certs.add(cert);
      CertPath path = cf.generateCertPath(certs);

      Set<TrustAnchor> trustAnchors = new HashSet<>();
      trustAnchors.add(new TrustAnchor(this.certificate, null));
      PKIXParameters params = new PKIXParameters(trustAnchors);
      params.setRevocationEnabled(false);

      CertPathValidator validator = CertPathValidator.getInstance("PKIX");
      validator.validate(path, params);
    }

    // 4. Output to PKCS#7 format
    // return SecurityUtils.genCMSCertOnlyMessage(cert);
    return cert;
  }

  public CBORObject signCommissionerToken(CBORObject token) throws Exception {
    return signCommissionerToken(
        token,
        privateKey,
        SecurityUtils.COSE_SIGNATURE_ALGORITHM,
        SecurityUtils.getSubjectKeyId(getCertificate()));
  }

  public static CBORObject signCommissionerToken(
      CBORObject token, PrivateKey signingKey, CBORObject signingAlg, byte[] subjectKeyId)
      throws Exception {
    Map<Short, CBORObject> claims = new HashMap<>();

    Object aud = token.get(CBORObject.FromObject(se.sics.ace.Constants.AUD));
    claims.put(se.sics.ace.Constants.AUD, CBORObject.FromObject(aud));

    // TODO(wgtdkp): verify the COSE_KEY with commissioner certificate presented by DTLS handshake
    CBORObject cnf = CBORObject.NewMap();
    CBORObject tokenCnf = token.get(CBORObject.FromObject(se.sics.ace.Constants.REQ_CNF));
    cnf.Add(
        se.sics.ace.Constants.COSE_KEY,
        tokenCnf.get(CBORObject.FromObject(se.sics.ace.Constants.COSE_KEY)));
    claims.put(se.sics.ace.Constants.CNF, cnf);

    String keyId = new String(subjectKeyId);
    claims.put(se.sics.ace.Constants.ISS, CBORObject.FromObject(keyId));

    Date expire =
        new Date(System.currentTimeMillis() + 3600 * 24 * 1000 * Constants.COM_TOK_VALIDITY);
    claims.put(se.sics.ace.Constants.EXP, CBORObject.FromObject(Voucher.dateToYoungFormat(expire)));

    OneKey oneKey = new OneKey(null, signingKey);
    CwtCryptoCtx ctx = CwtCryptoCtx.sign1Create(oneKey, signingAlg);

    CWT cwt = new CWT(claims);
    return cwt.encode(ctx);
  }

  public X500Name getSubjectName() {
    return new X500Name(getCertificate().getIssuerX500Principal().getName());
  }

  private static BigInteger serialNumber = new BigInteger("1");

  private static final synchronized BigInteger allocateSerialNumber() {
    serialNumber = serialNumber.add(BigInteger.ONE);
    logger.info("allocate serial number: " + serialNumber);
    return serialNumber;
  }

  private String domainName;

  private PrivateKey privateKey;

  private X509Certificate certificate;

  private static Logger logger = Logger.getLogger(DomainCA.class.getCanonicalName());
}
