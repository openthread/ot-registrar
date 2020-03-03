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

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.eclipse.californium.elements.util.SslContextUtil;

public class Credentials {
  public Credentials(String file, String alias, String password) throws Exception {
    this.alias = alias;
    this.password = password;
    this.keyStore = KeyStore.getInstance(Constants.KEY_STORE_FORMAT);

    try (InputStream in = new FileInputStream(file)) {
      keyStore.load(in, password.toCharArray());
    }
  }

  // Returns null if alias not included.
  public PrivateKey getPrivateKey() throws Exception {
    return (PrivateKey) keyStore.getKey(alias, password.toCharArray());
  }

  // Returns null if alias not included.
  public X509Certificate getCertificate() throws KeyStoreException {
    return (X509Certificate) keyStore.getCertificate(alias);
  }

  // Returns null if alias not included.
  public X509Certificate[] getCertificateChain() throws KeyStoreException {
    return SslContextUtil.asX509Certificates(keyStore.getCertificateChain(alias));
  }

  private String alias;
  private String password;
  private KeyStore keyStore;
}
