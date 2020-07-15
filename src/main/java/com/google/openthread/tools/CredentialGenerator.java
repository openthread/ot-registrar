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

package com.google.openthread.tools;

import com.google.openthread.Constants;
import com.google.openthread.HardwareModuleName;
import com.google.openthread.SecurityUtils;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.Reader;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.OtherName;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

public class CredentialGenerator {
  public static final String PASSWORD = "OpenThread";

  public static final String DNAME_PREFIX = "C=CN,L=SH,O=Google,OU=OpenThread,CN=";

  public static final String DOMAINCA_ALIAS = "domainca";
  public static final String DOMAINCA_DNAME = DNAME_PREFIX + DOMAINCA_ALIAS;

  public static final String REGISTRAR_ALIAS = "registrar";
  public static final String REGISTRAR_DNAME = DNAME_PREFIX + REGISTRAR_ALIAS;

  public static final String COMMISSIONER_ALIAS = "commissioner";
  public static final String COMMISSIONER_DNAME = DNAME_PREFIX + COMMISSIONER_ALIAS;

  public static final String MASA_ALIAS = "masa";
  public static final String MASA_DNAME = DNAME_PREFIX + MASA_ALIAS;
  public static final String MASA_URI = "localhost:5685";

  public static final String PLEDGE_ALIAS = "pledge";
  public static final String PLEDGE_SN = "OT-9527";
  public static final String PLEDGE_DNAME =
      DNAME_PREFIX + PLEDGE_ALIAS + ",SERIALNUMBER=" + PLEDGE_SN;

  // Fields provided for testing, shouldn't reference outside of tests.
  public KeyPair masaKeyPair;
  public X509Certificate masaCert;
  public KeyPair pledgeKeyPair;
  public X509Certificate pledgeCert;

  public KeyPair domaincaKeyPair;
  public X509Certificate domaincaCert;
  public KeyPair registrarKeyPair;
  public X509Certificate registrarCert;
  public KeyPair commissionerKeyPair;
  public X509Certificate commissionerCert;

  public X509Certificate genSelfSignedCert(KeyPair keyPair, String dname) throws Exception {
    return SecurityUtils.genCertificate(keyPair, dname, keyPair, dname, true, null);
  }

  public X509Certificate genPledgeCertificate(
      KeyPair subKeyPair,
      String subName,
      KeyPair issuerKeyPair,
      String issuerName,
      HardwareModuleName moduleName,
      String masaUri)
      throws Exception {

    Extension keyUsage =
        new Extension(
            Extension.keyUsage,
            true,
            new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
                .getEncoded(ASN1Encoding.DER));

    OtherName otherName =
        new OtherName(new ASN1ObjectIdentifier(Constants.HARDWARE_MODULE_NAME_OID), moduleName);
    Extension subjectAltName =
        new Extension(
            Extension.subjectAlternativeName,
            false,
            new GeneralNames(new GeneralName(GeneralName.otherName, otherName))
                .getEncoded(ASN1Encoding.DER));

    // FIXME(wgtdkp): we are not sure if the method of access description is id-ad-caIssuer
    /*
    AuthorityInformationAccess aiaExt =
        new AuthorityInformationAccess(
            X509ObjectIdentifiers.id_ad_caIssuers, SecurityUtils.genMasaUri(masaUri));
    Extension masaUriExt =
        new Extension(Extension.authorityInfoAccess, false, aiaExt.getEncoded(ASN1Encoding.DER));
        DERIA5String
    */
    Extension masaUriExt =
        new Extension(
            new ASN1ObjectIdentifier(Constants.MASA_URI_OID).intern(),
            false,
            new DERIA5String(MASA_URI).getEncoded());

    List<Extension> extensions = new ArrayList<>();
    extensions.add(keyUsage);
    extensions.add(subjectAltName);
    extensions.add(masaUriExt);
    return SecurityUtils.genCertificate(
        subKeyPair, subName, issuerKeyPair, issuerName, false, extensions);
  }

  public void make(String[] caCertKeyFiles, String[] masaCertKeyFiles) throws Exception {

    HardwareModuleName hwModuleName =
        new HardwareModuleName(Constants.PRIVATE_HARDWARE_TYPE_OID, PLEDGE_SN.getBytes());

    if (masaCertKeyFiles != null) {
      try (Reader reader = new FileReader(masaCertKeyFiles[0])) {
        masaCert = SecurityUtils.parseCertFromPem(reader);
      }
      try (Reader reader = new FileReader(masaCertKeyFiles[1])) {
        masaKeyPair =
            new KeyPair(masaCert.getPublicKey(), SecurityUtils.parsePrivateKeyFromPem(reader));
      }
    } else {
      masaKeyPair = SecurityUtils.genKeyPair();
      masaCert = genSelfSignedCert(masaKeyPair, MASA_DNAME);
    }
    pledgeKeyPair = SecurityUtils.genKeyPair();
    pledgeCert =
        genPledgeCertificate(
            pledgeKeyPair,
            PLEDGE_DNAME,
            masaKeyPair,
            masaCert.getSubjectX500Principal().getName(),
            hwModuleName,
            MASA_URI);

    if (caCertKeyFiles != null) {
      try (Reader reader = new FileReader(caCertKeyFiles[0])) {
        domaincaCert = SecurityUtils.parseCertFromPem(reader);
      }
      try (Reader reader = new FileReader(caCertKeyFiles[1])) {
        domaincaKeyPair =
            new KeyPair(domaincaCert.getPublicKey(), SecurityUtils.parsePrivateKeyFromPem(reader));
      }
    } else {
      domaincaKeyPair = SecurityUtils.genKeyPair();
      domaincaCert = genSelfSignedCert(domaincaKeyPair, DOMAINCA_DNAME);
    }
    registrarKeyPair = SecurityUtils.genKeyPair();
    registrarCert =
        SecurityUtils.genCertificate(
            registrarKeyPair,
            REGISTRAR_DNAME,
            domaincaKeyPair,
            domaincaCert.getSubjectX500Principal().getName(),
            false,
            null);
    commissionerKeyPair = SecurityUtils.genKeyPair();
    commissionerCert =
        SecurityUtils.genCertificate(
            commissionerKeyPair,
            COMMISSIONER_DNAME,
            domaincaKeyPair,
            domaincaCert.getSubjectX500Principal().getName(),
            false,
            null);
  }

  public void store(String filename) throws Exception {
    char[] password = PASSWORD.toCharArray();

    KeyStore ks = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);
    ks.load(null, PASSWORD.toCharArray());

    ks.setKeyEntry(
        MASA_ALIAS, masaKeyPair.getPrivate(), password, new X509Certificate[] {masaCert});
    ks.setKeyEntry(
        PLEDGE_ALIAS,
        pledgeKeyPair.getPrivate(),
        password,
        new X509Certificate[] {pledgeCert, masaCert});
    ks.setKeyEntry(
        DOMAINCA_ALIAS,
        domaincaKeyPair.getPrivate(),
        password,
        new X509Certificate[] {domaincaCert});
    ks.setKeyEntry(
        REGISTRAR_ALIAS,
        registrarKeyPair.getPrivate(),
        password,
        new X509Certificate[] {registrarCert, domaincaCert});
    ks.setKeyEntry(
        COMMISSIONER_ALIAS,
        commissionerKeyPair.getPrivate(),
        password,
        new X509Certificate[] {commissionerCert, domaincaCert});

    File file = new File(filename);
    file.createNewFile();
    try (OutputStream os = new FileOutputStream(file, false)) {
      ks.store(os, password);
    }
  }

  public void dumpSeparateFiles() throws Exception {
    String[] files = {
      MASA_ALIAS, PLEDGE_ALIAS, DOMAINCA_ALIAS, REGISTRAR_ALIAS, COMMISSIONER_ALIAS
    };
    KeyPair[] keys = {
      masaKeyPair, pledgeKeyPair, domaincaKeyPair, registrarKeyPair, commissionerKeyPair
    };
    X509Certificate[] certs = {masaCert, pledgeCert, domaincaCert, registrarCert, commissionerCert};
    for (int i = 0; i < files.length; ++i) {
      File kf = new File(files[i] + "_private.pem");
      kf.createNewFile();
      try (OutputStream os = new FileOutputStream(kf, false)) {
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(os));
        writer.writeObject(keys[i].getPrivate());
        writer.close();

        // Verify the key in PEM file
        // PrivateKey pk = parsePrivateKey(kf.getName());
        // if (!Arrays.equals(pk.getEncoded(), keys[i].getPrivate().getEncoded())) {
        //    throw new UnrecoverableKeyException("bad private key in PEM file");
        // }
      }

      File cf = new File(files[i] + "_cert.pem");
      cf.createNewFile();
      try (OutputStream os = new FileOutputStream(cf, false)) {
        JcaPEMWriter writer = new JcaPEMWriter(new PrintWriter(os));
        writer.writeObject(certs[i]);
        writer.close();

        // Verify the cert in PEM file
        // X509Certificate cert = parseCertificate(cf.getName());
      }
    }
  }

  public static void main(String[] args) {
    final String HELP_FORMAT =
        "CredentialGenerator [-c <domain-ca-cert> <domain-ca-key>] [-m <masa-ca-cert> <masa-ca-key>] -o <output-file>";

    HelpFormatter helper = new HelpFormatter();
    Options options = new Options();

    Option fileOpt =
        Option.builder("o")
            .longOpt("out")
            .hasArg()
            .argName("output-file")
            .desc("the keystore file write to")
            .build();

    Option dumpOpt =
        Option.builder("d")
            .longOpt("dump")
            .hasArg(false)
            .desc("dump the certificates as separate PEM files")
            .build();

    Option caOpt =
        Option.builder("c")
            .longOpt("ca")
            .hasArg()
            .desc("domain CA root key & certificate file")
            .build();
    caOpt.setArgs(2);

    Option masaOpt =
        Option.builder("m")
            .longOpt("masa")
            .hasArg()
            .desc("MASA CA root key & certificate file")
            .build();
    masaOpt.setArgs(2);

    Option helpOpt =
        Option.builder("h").longOpt("help").hasArg(false).desc("print this message").build();

    options
        .addOption(fileOpt)
        .addOption(helpOpt)
        .addOption(dumpOpt)
        .addOption(caOpt)
        .addOption(masaOpt);

    try {
      CommandLineParser parser = new DefaultParser();
      CommandLine cmd = parser.parse(options, args);

      if (cmd.hasOption('h')) {
        helper.printHelp(HELP_FORMAT, options);
        return;
      }

      String keyStoreFile = cmd.getOptionValue('o');
      if (keyStoreFile == null) {
        throw new IllegalArgumentException("need to specify keystore file!");
      }

      CredentialGenerator cg = new CredentialGenerator();
      cg.make(cmd.getOptionValues("c"), cmd.getOptionValues("m"));
      cg.store(keyStoreFile);

      if (cmd.hasOption('d')) {
        cg.dumpSeparateFiles();
      }
    } catch (Exception e) {
      System.err.println("error: " + e.getMessage());
      e.printStackTrace();
      helper.printHelp(HELP_FORMAT, options);
      return;
    }
  }
}
