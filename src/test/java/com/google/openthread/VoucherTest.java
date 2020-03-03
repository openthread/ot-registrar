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

import com.google.openthread.brski.*;
import java.util.Arrays;
import java.util.Date;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class VoucherTest {

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testYoungDate() throws Exception {
    Date date = new Date();
    String young = Voucher.dateToYoungFormat(date);
    Date date2 = Voucher.dateFromYoungFormat(young);

    Assert.assertTrue(date.getTime() == date2.getTime());
  }

  @Test
  public void testSimple() {
    Voucher v1 = new Voucher();
    v1.assertion = Voucher.Assertion.PROXIMITY;
    v1.createdOn = new Date();
    v1.expiresOn = new Date();

    v1.serialNumber = "12345";
    v1.pinnedDomainCert = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(v1.validate());

    byte[] data = new CBORSerializer().serialize(v1);

    Voucher v2 = new CBORSerializer().deserialize(data);
    Assert.assertTrue(v2.validate());

    Assert.assertTrue(v1.assertion.equals(v2.assertion));
    Assert.assertTrue(v1.serialNumber.equals(v2.serialNumber));
    Assert.assertTrue(Arrays.equals(v1.pinnedDomainCert, v2.pinnedDomainCert));
  }

  @Test
  public void testSimpleRequest() {
    VoucherRequest vr1 = new VoucherRequest();
    vr1.assertion = Voucher.Assertion.PROXIMITY;
    vr1.serialNumber = "12345";
    vr1.proximityRegistrarCert = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(vr1.validate());

    byte[] data = new CBORSerializer().serialize(vr1);

    VoucherRequest vr2 = (VoucherRequest) new CBORSerializer().deserialize(data);
    Assert.assertTrue(vr2.validate());

    Assert.assertTrue(vr1.assertion.equals(vr2.assertion));
    Assert.assertTrue(vr1.serialNumber.equals(vr2.serialNumber));
    Assert.assertTrue(Arrays.equals(vr1.proximityRegistrarCert, vr2.proximityRegistrarCert));
  }

  @Test
  public void testSimpleConstrained() {
    ConstrainedVoucher cv1 = new ConstrainedVoucher();
    cv1.assertion = Voucher.Assertion.PROXIMITY;
    cv1.serialNumber = "12345";
    cv1.createdOn = new Date();
    cv1.expiresOn = new Date();

    cv1.pinnedDomainSPKI = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(cv1.validate());

    byte[] data = new CBORSerializer().serialize(cv1);

    ConstrainedVoucher cv2 = (ConstrainedVoucher) new CBORSerializer().deserialize(data);
    Assert.assertTrue(cv2.validate());

    Assert.assertTrue(cv1.assertion.equals(cv2.assertion));
    Assert.assertTrue(cv1.serialNumber.equals(cv2.serialNumber));
    Assert.assertTrue(Arrays.equals(cv1.pinnedDomainSPKI, cv2.pinnedDomainSPKI));
  }

  @Test
  public void testSimpleConstrainedRequest() {
    ConstrainedVoucherRequest cvr1 = new ConstrainedVoucherRequest();
    cvr1.assertion = Voucher.Assertion.PROXIMITY;
    cvr1.serialNumber = "123";

    cvr1.proximityRegistrarSPKI = new byte[] {0x01, 0x02, 0x03};

    Assert.assertTrue(cvr1.validate());

    byte[] data = new CBORSerializer().serialize(cvr1);

    ConstrainedVoucherRequest cvr2 =
        (ConstrainedVoucherRequest) new CBORSerializer().deserialize(data);
    Assert.assertTrue(cvr2.validate());

    Assert.assertTrue(cvr1.assertion.equals(cvr2.assertion));
    Assert.assertTrue(cvr1.serialNumber.equals(cvr2.serialNumber));
    Assert.assertTrue(Arrays.equals(cvr1.proximityRegistrarSPKI, cvr2.proximityRegistrarSPKI));
  }
}
