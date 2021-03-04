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

package com.google.openthread;

import COSE.AlgorithmID;
import COSE.Attribute;
import COSE.CoseException;
import COSE.HeaderKeys;
import COSE.OneKey;
import COSE.Sign1Message;
import com.upokecenter.cbor.CBORObject;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.bc.BcX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.eclipse.californium.core.network.CoapEndpoint;
import org.eclipse.californium.scandium.DTLSConnector;
import org.eclipse.californium.scandium.config.DtlsConnectorConfig;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.CertificateType;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.cipher.CipherSuite;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;

/** Provides common security-related definitions and functionalities. */
public class SecurityUtils {
  static {
    BouncyCastleInitializer.init();
  }

  public static final String KEY_ALGORITHM = "EC";

  public static final int KEY_SIZE = 256;

  public static final String SIGNATURE_ALGORITHM = "SHA256withECDSA";

  public static final CBORObject COSE_SIGNATURE_ALGORITHM = AlgorithmID.ECDSA_256.AsCBOR();

  /**
   * Extract serialNumber from subject extension of given certificate.
   *
   * @param cert
   * @return the serialNumber if present, otherwise null;
   * @throws CertificateEncodingException
   */
  public static String getSerialNumber(X509Certificate cert) throws CertificateEncodingException {
    X500Name subject = new JcaX509CertificateHolder(cert).getSubject();
    RDN[] serialNumbers = subject.getRDNs(BCStyle.SERIALNUMBER);
    if (serialNumbers == null || serialNumbers.length == 0) {
      return null;
    }
    ASN1String str = DERPrintableString.getInstance(serialNumbers[0].getFirst().getValue());
    return str.getString();
  }

  /**
   * Extract the hardwareModuleName extension from given certificate.
   *
   * @param cert
   * @return hardwareModuleName if present, otherwise null;
   * @throws CertificateEncodingException
   */
  public static HardwareModuleName getHWModuleName(X509Certificate cert)
      throws CertificateEncodingException {
    Extensions exts = new JcaX509CertificateHolder(cert).getExtensions();
    for (Object obj :
        GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName).getNames()) {
      GeneralName name = GeneralName.getInstance(obj);
      if (name.getTagNo() == GeneralName.otherName) {
        OtherName otherName = OtherName.getInstance(name.getName());
        if (otherName.getTypeID().getId().equals(Constants.HARDWARE_MODULE_NAME_OID)) {
          return HardwareModuleName.getInstance(otherName.getValue());
        }
      }
    }
    return null;
  }

  /**
   * Extract the dnsName subfield of the SubjectAltName extension.
   *
   * @param cert
   * @return the dnsName subfield of the SubjectAltName extension if present, otherwise null;
   */
  public static String getDNSName(X509Certificate cert) throws CertificateEncodingException {
    Extensions exts = new JcaX509CertificateHolder(cert).getExtensions();
    for (Object obj :
        GeneralNames.fromExtensions(exts, Extension.subjectAlternativeName).getNames()) {
      GeneralName name = GeneralName.getInstance(obj);
      if (name.getTagNo() == GeneralName.dNSName) {
        return name.getName().toString();
      }
    }
    return null;
  }

  public static String getMasaUri(X509Certificate cert) {
    try {
      X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
      Extension masaUri = holder.getExtension(new ASN1ObjectIdentifier(Constants.MASA_URI_OID));
      return DERIA5String.fromByteArray(masaUri.getExtnValue().getOctets()).toString();
    } catch (IOException e) {
      e.printStackTrace();
      return null;
    } catch (CertificateEncodingException e) {
      e.printStackTrace();
      return null;
    }
  }

  public static String getMasaUri(GeneralName name) {
    if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
      return null;
    }
    return DERIA5String.getInstance(name.getName()).getString();
  }

  public static GeneralName genMasaUri(String masaUri) {
    return new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(masaUri));
  }

  public static String toPEMFormat(Object csr) throws IOException {
    StringWriter str = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(str);
    pemWriter.writeObject(csr);
    pemWriter.close();
    str.close();
    return str.toString();
  }

  public static X509Certificate parseCertFromPem(Reader reader) throws Exception {
    PEMParser parser = new PEMParser(reader);
    return new JcaX509CertificateConverter()
        .getCertificate((X509CertificateHolder) parser.readObject());
  }

  public static PrivateKey parsePrivateKeyFromPem(Reader reader) throws Exception {
    PEMParser parser = new PEMParser(reader);
    Object obj = parser.readObject();
    PrivateKeyInfo pkInfo;
    if (obj instanceof PEMKeyPair) {
      pkInfo = ((PEMKeyPair) obj).getPrivateKeyInfo();
    } else if (obj instanceof PrivateKeyInfo) {
      pkInfo = (PrivateKeyInfo) obj;
    } else {
      throw new Exception("the key file is corrupted");
    }
    return new JcaPEMKeyConverter().getPrivateKey(pkInfo);
  }

  /** get the content of subject-key-identifier extension without any encoding. */
  public static byte[] getSubjectKeyId(X509Certificate cert) throws IOException {
    // TODO(wgtdkp): use bouncycastle ?
    ASN1OctetString octets =
        DEROctetString.getInstance(cert.getExtensionValue(Extension.subjectKeyIdentifier.getId()));
    if (octets == null) {
      // Create subject key identifier if the certificate doesn't include it.
      return SecurityUtils.createSubjectKeyId(cert.getPublicKey()).getEncoded();
    } else {
      octets = DEROctetString.getInstance(octets.getOctets());
      return octets.getOctets();
    }
  }

  public static byte[] getAuthorityKeyId(X509Certificate cert) {
    ASN1OctetString octets =
        DEROctetString.getInstance(
            cert.getExtensionValue(Extension.authorityKeyIdentifier.getId()));
    if (octets == null) {
      return null;
    }
    AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(octets.getOctets());
    return aki.getKeyIdentifier();
  }

  public static byte[] genCoseSign1Message(
      PrivateKey signingKey, CBORObject signingAlg, byte[] content) throws CoseException {
    Sign1Message msg = new Sign1Message();
    msg.addAttribute(HeaderKeys.Algorithm, signingAlg, Attribute.PROTECTED);
    msg.SetContent(content);
    msg.sign(new OneKey(null, signingKey));
    return msg.EncodeToBytes();
  }

  public static byte[] genCMSSignedMessage(
      PrivateKey signingKey,
      X509Certificate signingCert,
      String signingAlg,
      X509Certificate[] certs,
      byte[] content)
      throws Exception {
    ContentSigner signer = new JcaContentSignerBuilder(signingAlg).build(signingKey);
    X509CertificateHolder holder = new JcaX509CertificateHolder(signingCert);
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    SignerInfoGenerator infoGen =
        new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().build())
            .build(signer, holder);
    generator.addSignerInfoGenerator(infoGen);
    for (X509Certificate cert : certs) {
      generator.addCertificate(new JcaX509CertificateHolder(cert));
    }

    CMSTypedData data = new CMSProcessableByteArray(content);
    CMSSignedData signedData = generator.generate(data, true);
    if (!validateCMSSignedMessage(signedData)) {
      throw new CMSException("validation of CMSSignedData failed");
    }

    return signedData.getEncoded();
  }

  public static CMSSignedData genCMSCertOnlyMessage(X509Certificate cert) throws Exception {
    CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
    X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
    generator.addCertificate(holder);

    // Empty data
    CMSTypedData data = new CMSProcessableByteArray(new byte[] {});
    return generator.generate(data, true);
  }

  public static boolean validateCMSSignedMessage(CMSSignedData signedData) throws Exception {
    Store<X509CertificateHolder> certs = signedData.getCertificates();
    SignerInformationStore signers = signedData.getSignerInfos();

    for (SignerInformation signerInfo : signers.getSigners()) {
      X509CertificateHolder holder =
          (X509CertificateHolder) certs.getMatches(signerInfo.getSID()).iterator().next();

      SignerInformationVerifier verifier = new JcaSimpleSignerInfoVerifierBuilder().build(holder);
      return signerInfo.verify(verifier);
    }
    return false;
  }

  public static byte[] decodeCMSSignedMessage(byte[] msg, List<X509Certificate> certs)
      throws Exception {
    CMSSignedData signedData = new CMSSignedData(msg);
    if (!validateCMSSignedMessage(signedData)) {
      return null;
    }

    for (X509CertificateHolder holder : signedData.getCertificates().getMatches(null)) {
      certs.add(new JcaX509CertificateConverter().getCertificate(holder));
    }
    return (byte[]) signedData.getSignedContent().getContent();
  }

  public static KeyPair genKeyPair()
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
    return genKeyPair(SecurityUtils.KEY_ALGORITHM, SecurityUtils.KEY_SIZE);
  }

  public static KeyPair genKeyPair(String algorithm, int keySize)
      throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchProviderException {
    KeyPairGenerator gen = KeyPairGenerator.getInstance(algorithm, "BC");
    gen.initialize(new ECGenParameterSpec("prime256v1"), new SecureRandom());
    return gen.generateKeyPair();
  }

  /**
   * Generate a certificate with default signature and digest algorithm.
   *
   * @param subKeyPair subject key pair
   * @param subName subject distinguished name
   * @param issuerKeyPair issuer key pair
   * @param issuerName issuer distinguished name
   * @param ca is this certificate used as a CA
   * @param extensions additional extensions
   * @return generated certificate
   * @throws Exception
   */
  public static X509Certificate genCertificate(
      KeyPair subKeyPair,
      String subName,
      KeyPair issuerKeyPair,
      String issuerName,
      boolean ca,
      List<Extension> extensions)
      throws Exception {
    PublicKey subPub = subKeyPair.getPublic();
    PrivateKey issPriv = issuerKeyPair.getPrivate();
    PublicKey issPub = issuerKeyPair.getPublic();

    X509v3CertificateBuilder v3CertGen =
        new JcaX509v3CertificateBuilder(
            new X500Name(issuerName),
            allocateSerialNumber(),
            new Date(System.currentTimeMillis()),
            new Date(System.currentTimeMillis() + (1000L * 3600 * 24 * Constants.CERT_VALIDITY)),
            new X500Name(subName),
            subPub);

    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);

    // Default extensions
    v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, createSubjectKeyId(subPub));

    v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, createAuthorityKeyId(issPub));

    v3CertGen.addExtension(Extension.basicConstraints, false, new BasicConstraints(ca));

    // Additional extensions
    if (extensions != null) {
      for (Extension ext : extensions) {
        v3CertGen.addExtension(ext);
      }
    }

    X509Certificate cert =
        new JcaX509CertificateConverter()
            .getCertificate(v3CertGen.build(contentSignerBuilder.build(issPriv)));

    cert.checkValidity(new Date());
    cert.verify(issPub);

    return cert;
  }

  public static X509Certificate loadX509Certificate(String certFile)
      throws CertificateException, IOException {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    FileInputStream is = new FileInputStream(certFile);
    X509Certificate cert = (X509Certificate) cf.generateCertificate(is);
    is.close();
    return cert;
  }

  public static final class DoNothingVerifier implements CertificateVerifier {

    public DoNothingVerifier(X509Certificate[] rootCertificates) {
      this.rootCertificates = rootCertificates;
    }

    @Override
    public void verifyCertificate(CertificateMessage message, DTLSSession session) {
      // We do nothing to accept the peer
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return rootCertificates;
    }

    private X509Certificate[] rootCertificates;
  }

  public static final CoapEndpoint genCoapClientEndPoint(
      X509Certificate[] trustAnchors, PrivateKey privateKey, X509Certificate[] certificateChain) {
    return genCoapClientEndPoint(trustAnchors, privateKey, certificateChain, null);
  }

  public static final CoapEndpoint genCoapClientEndPoint(
      X509Certificate[] trustAnchors,
      PrivateKey privateKey,
      X509Certificate[] certificateChain,
      CertificateVerifier verifier) {
    return genCoapEndPoint(-1, trustAnchors, privateKey, certificateChain, verifier);
  }

  public static final CoapEndpoint genCoapServerEndPoint(
      int port,
      X509Certificate[] trustAnchors,
      PrivateKey privateKey,
      X509Certificate[] certificateChain,
      CertificateVerifier verifier) {
    assert (port >= 0);
    return genCoapEndPoint(port, trustAnchors, privateKey, certificateChain, verifier);
  }

  private static final CoapEndpoint genCoapEndPoint(
      int port,
      X509Certificate[] trustAnchors,
      PrivateKey privateKey,
      X509Certificate[] certificateChain,
      CertificateVerifier verifier) {
    DtlsConnectorConfig.Builder config = new DtlsConnectorConfig.Builder();

    config.setSupportedCipherSuites(CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8);

    config.setRetransmissionTimeout(10 * 1000);

    // Set Max Fragment Length to 2^10 bytes.
    config.setMaxFragmentLengthCode(2);

    // OpenThread CoAP doesn't handle fragments, so it still fails
    config.setMaxTransmissionUnit(1024);

    if (port >= 0) {
      // Server
      config.setServerOnly(true).setAddress(new InetSocketAddress(port));
    } else {
      // Client
      config.setClientOnly().setSniEnabled(false);
    }

    config.setTrustStore(trustAnchors);

    if (verifier != null) {
      config.setCertificateVerifier(verifier);
    }

    List<CertificateType> types = new ArrayList<>();

    types.add(CertificateType.X_509);
    config.setIdentity(privateKey, certificateChain, types);

    DTLSConnector connector = new DTLSConnector(config.build());
    return new CoapEndpoint.Builder().setConnector(connector).build();
  }

  // As defined in 4.2.1.2 of RFC 5280, authority key identifier (subject key identifier of CA)
  // must be calculated by SHA1.
  private static final X509ExtensionUtils extUtils = new BcX509ExtensionUtils();

  static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
    return createSubjectKeyId(SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
  }

  static SubjectKeyIdentifier createSubjectKeyId(SubjectPublicKeyInfo pubKey) {
    return extUtils.createSubjectKeyIdentifier(pubKey);
  }

  private static AuthorityKeyIdentifier createAuthorityKeyId(PublicKey pubKey) {
    return extUtils.createAuthorityKeyIdentifier(
        SubjectPublicKeyInfo.getInstance(pubKey.getEncoded()));
  }

  private static BigInteger serialNumber = BigInteger.ZERO;

  public static BigInteger allocateSerialNumber() {
    serialNumber = serialNumber.add(BigInteger.ONE);
    return serialNumber;
  }
}
