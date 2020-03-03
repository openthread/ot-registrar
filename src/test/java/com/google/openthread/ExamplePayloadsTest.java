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

import com.google.openthread.brski.CBORSerializer;
import com.google.openthread.brski.ConstrainedVoucher;
import com.google.openthread.brski.ConstrainedVoucherRequest;
import com.google.openthread.brski.Voucher;
import com.google.openthread.commissioner.Commissioner;
import com.google.openthread.pledge.Pledge;
import com.google.openthread.registrar.CSRAttributes;
import com.upokecenter.cbor.CBORObject;
import java.security.KeyPair;
import java.util.Date;
import org.bouncycastle.asn1.est.CsrAttrs;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class ExamplePayloadsTest {

  @Test
  public void voucherExamplePayload() throws Exception {
    ConstrainedVoucherRequest cvr = new ConstrainedVoucherRequest();
    cvr.assertion = Voucher.Assertion.PROXIMITY;
    cvr.serialNumber = "123";
    cvr.nonce = Pledge.generateNonce();

    KeyPair kp = SecurityUtils.genKeyPair();
    cvr.proximityRegistrarSPKI =
        SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()).getEncoded();
    Assert.assertTrue(cvr.validate());

    System.out.println("example constrained voucher request payload:");
    System.out.println(new CBORSerializer().toCBOR(cvr));

    ConstrainedVoucher cv = new ConstrainedVoucher();
    cv.assertion = Voucher.Assertion.PROXIMITY;
    cv.createdOn = new Date();
    cv.serialNumber = "123";
    cv.nonce = cvr.nonce;

    kp = SecurityUtils.genKeyPair();
    cv.pinnedDomainSPKI =
        SubjectPublicKeyInfo.getInstance(kp.getPublic().getEncoded()).getEncoded();
    Assert.assertTrue(cv.validate());

    System.out.println("example constrained voucher payload:");
    System.out.println(new CBORSerializer().toCBOR(cv));
  }

  @Test
  public void csrAttrsExamplePayload() throws Exception {
    CSRAttributes attrs = new CSRAttributes(CSRAttributes.DEFAULT_FILE);

    CsrAttrs csrAttrs = new CsrAttrs(attrs.getAttrAndOids());
    CBORObject resp = CBORObject.FromObject(csrAttrs.getEncoded());
    System.out.println("example CSR attributes response:");
    System.out.println(resp);
    System.out.println("the cbor encoeded:");
    System.out.println(Hex.toHexString(resp.EncodeToBytes()));
  }

  @Test
  public void comTokenExamplePayload() throws Exception {
    KeyPair kp = SecurityUtils.genKeyPair();
    CBORObject req = Commissioner.genTokenRequest("OpenThread-TCE-TEST", kp.getPublic());
    System.out.println("exmaple COM_TOK.req payload:");
    System.out.println(req);
  }
}
