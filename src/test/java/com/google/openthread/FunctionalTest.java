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

import static org.junit.Assert.assertSame;

import com.google.openthread.brski.ConstrainedVoucher;
import com.google.openthread.commissioner.Commissioner;
import com.google.openthread.domainca.DomainCA;
import com.google.openthread.masa.MASA;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.registrar.Registrar;
import com.google.openthread.registrar.RegistrarBuilder;
import com.google.openthread.tools.CredentialGenerator;
import java.security.KeyPair;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.eclipse.californium.core.CoapResponse;
import org.eclipse.californium.core.coap.CoAP;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import se.sics.ace.cwt.CWT;

public class FunctionalTest {

  private static final String REGISTRAR_URI =
      "coaps://[::1]:" + Constants.DEFAULT_REGISTRAR_COAPS_PORT;

  private static KeyPair domaincaKeyPair;
  private static X509Certificate domaincaCert;

  private static KeyPair registrarKeyPiar;
  private static X509Certificate registrarCert;

  private static KeyPair commissionerKeyPair;
  private static X509Certificate commissionerCert;

  private static KeyPair pledgeKeyPair;
  private static X509Certificate pledgeCert;

  private static KeyPair masaKeyPair;
  private static X509Certificate masaCert;

  private static final String DEFAULT_DOMAIN_NAME = "Thread-Test";
  private DomainCA domainCA;
  private Registrar registrar;
  private Commissioner commissioner;
  private Pledge pledge;
  private MASA masa;

  @Rule public ExpectedException thrown = ExpectedException.none();

  @BeforeClass
  public static void setup() throws Exception {
    CredentialGenerator cg = new CredentialGenerator();
    cg.make(null, null);
    domaincaKeyPair = cg.domaincaKeyPair;
    domaincaCert = cg.domaincaCert;

    registrarKeyPiar = cg.registrarKeyPair;
    registrarCert = cg.registrarCert;

    // Commissioner cert signed by domain ca
    commissionerKeyPair = cg.commissionerKeyPair;
    commissionerCert = cg.commissionerCert;

    masaKeyPair = cg.masaKeyPair;
    masaCert = cg.masaCert;

    pledgeKeyPair = cg.pledgeKeyPair;
    pledgeCert = cg.pledgeCert;
  }

  @AfterClass
  public static void tearDown() {}

  @Before
  public void init() throws Exception {
    masa = new MASA(masaKeyPair.getPrivate(), masaCert, Constants.DEFAULT_MASA_COAPS_PORT);
    pledge =
        new Pledge(
            pledgeKeyPair.getPrivate(),
            new X509Certificate[] {pledgeCert, masaCert},
            REGISTRAR_URI);

    domainCA = new DomainCA(DEFAULT_DOMAIN_NAME, domaincaKeyPair.getPrivate(), domaincaCert);

    RegistrarBuilder registrarBuilder = new RegistrarBuilder();
    registrar =
        registrarBuilder
            .setPrivateKey(registrarKeyPiar.getPrivate())
            .setCertificateChain(new X509Certificate[] {registrarCert, domaincaCert})
            .addMasaCertificate(masaCert)
            .build(Constants.DEFAULT_REGISTRAR_COAPS_PORT);
    registrar.setDomainCA(domainCA);

    commissioner =
        new Commissioner(
            commissionerKeyPair.getPrivate(),
            new X509Certificate[] {commissionerCert, domaincaCert});

    masa.start();
    registrar.start();
  }

  @After
  public void finalize() {
    pledge.shutdown();
    commissioner.shutdown();
    registrar.stop();
    masa.stop();
  }

  private void VerifyEnroll() throws Exception {
    X509Certificate cert = pledge.getOperationalCert();
    Assert.assertTrue(cert != null);

    String domainName = SecurityUtils.getDNSName(cert);
    Assert.assertTrue(domainName.equals(registrar.getDomainName()));
  }

  @Test
  public void testCertificateChainValidationWithSelf() throws Exception {
    thrown.expect(Exception.class);

    X509Certificate cert = registrarCert;

    Set<TrustAnchor> trustAnchors = new HashSet<>();
    trustAnchors.add(new TrustAnchor(cert, null));

    PKIXParameters params = new PKIXParameters(trustAnchors);

    params.setRevocationEnabled(false);

    CertPathValidator validator = CertPathValidator.getInstance("PKIX");

    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    List<Certificate> certs = new ArrayList<>();
    certs.add(cert);
    CertPath path = cf.generateCertPath(certs);
    validator.validate(path, params);
  }

  @Test
  public void testPledgeCertificate() {
    Assert.assertTrue(SecurityUtils.getMasaUri(pledgeCert).equals(CredentialGenerator.MASA_URI));
  }

  @Test
  public void testConnection() {
    CoapResponse response = pledge.sayHello();
    assertSame(CoAP.ResponseCode.CONTENT, response.getCode());
  }

  @Test
  public void testVoucherRequest() throws Exception {
    ConstrainedVoucher voucher = pledge.requestVoucher();

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testCsrAttrsRequest() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testEnroll() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();

    VerifyEnroll();

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testReenroll() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();
    VerifyEnroll();

    pledge.reenroll();
    VerifyEnroll();

    // TODO(wgtdkp): verify pledge state
  }

  @Test
  public void testReset() throws Exception {
    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();
    VerifyEnroll();

    pledge.reenroll();
    VerifyEnroll();

    pledge.reset();

    pledge.requestVoucher();
    pledge.requestCSRAttributes();
    pledge.enroll();
    VerifyEnroll();

    pledge.reenroll();
    VerifyEnroll();
  }

  @Test
  public void testSimpleCommissioning() throws Exception {
    CWT comTok = commissioner.requestToken("TestDomainTCE", REGISTRAR_URI);
  }

  @Test
  public void testMultiPledges() {
    PledgeThread[] threads = new PledgeThread[10];

    for (int i = 0; i < threads.length; ++i) {
      threads[i] = new PledgeThread();
    }
    for (PledgeThread thread : threads) {
      thread.start();
    }
    for (PledgeThread thread : threads) {
      try {
        thread.join();
      } catch (InterruptedException e) {
        System.out.print("join failed: " + e.getMessage());
      }
    }
  }

  private class PledgeThread extends Thread {
    @Override
    public void run() {
      try {
        pledge.requestVoucher();
        pledge.requestCSRAttributes();
        pledge.enroll();
        VerifyEnroll();

        pledge.reenroll();
        VerifyEnroll();
      } catch (Exception e) {
        System.out.println("pledge [" + this.getId() + "]failed");
        e.printStackTrace();
        assert (false);
      }
    }
  }
}
