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

import java.security.GeneralSecurityException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.eclipse.californium.scandium.dtls.AlertMessage;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertDescription;
import org.eclipse.californium.scandium.dtls.AlertMessage.AlertLevel;
import org.eclipse.californium.scandium.dtls.CertificateMessage;
import org.eclipse.californium.scandium.dtls.DTLSSession;
import org.eclipse.californium.scandium.dtls.HandshakeException;
import org.eclipse.californium.scandium.dtls.x509.CertificateVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PledgeCertificateVerifier implements CertificateVerifier {
  public PledgeCertificateVerifier(Set<TrustAnchor> trustAnchors) {
    this.trustAnchors = new HashSet<>();
    if (trustAnchors != null) {
      this.trustAnchors.addAll(trustAnchors);
    }

    logger = LoggerFactory.getLogger(PledgeCertificateVerifier.class);
  }

  @Override
  public void verifyCertificate(CertificateMessage message, DTLSSession session)
      throws HandshakeException {

    // We save the provisionally accepted registrar certificate chain, it will be verified
    // after we got the 'pinned-domain-subject-public-key-info' in voucher.
    peerCertPath = message.getCertificateChain();
    if (peerCertPath.getCertificates().size() == 0) {
      AlertMessage alert =
          new AlertMessage(AlertLevel.FATAL, AlertDescription.BAD_CERTIFICATE, session.getPeer());
      peerAccepted = false;
      throw new HandshakeException("No server certificates", alert);
    }

    try {
      if (isDoVerification() && !trustAnchors.isEmpty()) {
        PKIXParameters params = new PKIXParameters(trustAnchors);
        params.setRevocationEnabled(false);

        CertPathValidator validator = CertPathValidator.getInstance("PKIX");
        validator.validate(message.getCertificateChain(), params);
        logger.info("handshake - certificate validation succeed!");
      } else {
        // We do no verification here to provisionally accept registrar certificate
        logger.info("registrar provisionally accepted without verification!");
      }

      peerAccepted = true;
    } catch (GeneralSecurityException e) {
      logger.error("handshake - certificate validation failed: " + e.getMessage());
      e.printStackTrace();
      AlertMessage alert =
          new AlertMessage(
              AlertMessage.AlertLevel.FATAL,
              AlertMessage.AlertDescription.BAD_CERTIFICATE,
              session.getPeer());
      peerAccepted = false;
      throw new HandshakeException("Certificate chain could not be validated", alert, e);
    }
  }

  @Override
  public X509Certificate[] getAcceptedIssuers() {
    List<X509Certificate> res = new ArrayList<>();
    for (TrustAnchor ta : trustAnchors) {
      if (ta.getTrustedCert() != null) {
        res.add(ta.getTrustedCert());
      }
    }
    return res.toArray(new X509Certificate[res.size()]);
  }

  public void addTrustAnchor(TrustAnchor ta) {
    trustAnchors.add(ta);
  }

  public CertPath getPeerCertPath() {
    return peerCertPath;
  }

  public boolean isPeerAccepted() {
    return peerAccepted;
  }

  public void setDoVerification(boolean doVerification) {
    this.doVerification = doVerification;
  }

  public boolean isDoVerification() {
    return this.doVerification;
  }

  protected Set<TrustAnchor> trustAnchors;

  protected CertPath peerCertPath;

  protected boolean peerAccepted = false;

  protected boolean doVerification = false;

  protected Logger logger;
}
