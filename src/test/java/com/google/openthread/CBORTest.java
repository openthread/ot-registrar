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

import com.google.openthread.brski.Voucher;
import com.upokecenter.cbor.CBORObject;
import java.util.Date;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class CBORTest {

  @Test
  public void testSimple() {
    CBORObject request = CBORObject.NewMap();
    CBORObject container = CBORObject.NewMap();
    container.Add("created-on", (new Date()).toString());
    container.Add("expires-on", (new Date()).toString());
    container.Add("assertion", Voucher.Assertion.VERIFIED.toString());
    container.Add("serial-number", "JADA123456789");
    container.Add("idevid-issuer", Hex.decode("01020D0F"));
    container.Add("pinned-domain-cert", Hex.decode("01020D0F"));
    container.Add("domain-cert-revocation-checks", false);
    container.Add("last-renewal-date", (new Date()).toString());
    container.Add("proximity-registrar-subject-public-key-info", Hex.decode("01020D0F"));
    request.Add("constrained-voucher-request", container);

    String jsonStr = request.ToJSONString();
    CBORObject.FromJSONString(jsonStr);
  }
}
