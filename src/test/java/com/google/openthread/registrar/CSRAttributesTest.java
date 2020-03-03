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

package com.google.openthread.registrar;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.est.AttrOrOID;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class CSRAttributesTest {

  @Rule public ExpectedException thrown = ExpectedException.none();

  @Test
  public void testLoad() throws Exception {
    CSRAttributes attr = new CSRAttributes(CSRAttributes.DEFAULT_FILE);
  }

  @Test
  public void testAttrs() throws Exception {
    CSRAttributes attr = new CSRAttributes(CSRAttributes.DEFAULT_FILE);
    for (AttrOrOID entry : attr.getAttrAndOids()) {
      if (entry.getAttribute() != null) {
        System.out.println(
            entry.getAttribute().getAttrType().getId()
                + "="
                + ASN1ObjectIdentifier.getInstance(
                        entry.getAttribute().getAttrValues().getObjectAt(0))
                    .getId());
      } else if (entry.getOid() != null) {
        System.out.println(entry.getOid().getId());
      } else {
        throw new Exception("unexpected attribute");
      }
    }
  }

  @Test
  public void testVerifyAttrs() throws Exception {
    String jsonStr =
        "[\n"
            + "    // Attribute<ecPublicKey, prime256v1>\n"
            + "    {\"1.2.840.10045.2.1\" : \"1.2.840.10045.3.1.7\"},\n"
            + "\n"
            + "    // OID<ecdsa-with-SHA256>\n"
            + "    \"1.2.840.10045.4.3.2\"\n"
            + "]";

    try (InputStream in = new ByteArrayInputStream(jsonStr.getBytes())) {
      CSRAttributes attr = new CSRAttributes(in);

      Assert.assertEquals(attr.getAttrAndOids().length, 2);

      for (AttrOrOID entry : attr.getAttrAndOids()) {
        if (entry.getAttribute() != null) {
          Assert.assertTrue(entry.getAttribute().getAttrType().getId().equals("1.2.840.10045.2.1"));
          Assert.assertTrue(
              ASN1ObjectIdentifier.getInstance(entry.getAttribute().getAttrValues().getObjectAt(0))
                  .getId()
                  .equals("1.2.840.10045.3.1.7"));
        } else if (entry.getOid() != null) {
          Assert.assertTrue(entry.getOid().getId().equals("1.2.840.10045.4.3.2"));
        } else {
          throw new Exception("unexpected attribute");
        }
      }
    }
  }

  @Test
  public void testMultiValues() throws Exception {
    String jsonStr =
        "[{\"1.2.840.10045.2.1\" : [\"1.2.840.10045.3.1.7\", \"1.2.840.10045.3.1.8\"]}]";

    try (InputStream in = new ByteArrayInputStream(jsonStr.getBytes())) {
      CSRAttributes attr = new CSRAttributes(in);

      Assert.assertEquals(attr.getAttrAndOids().length, 1);

      for (AttrOrOID entry : attr.getAttrAndOids()) {
        if (entry.getAttribute() != null) {
          Assert.assertTrue(entry.getAttribute().getAttrType().getId().equals("1.2.840.10045.2.1"));
          Assert.assertTrue(
              ASN1ObjectIdentifier.getInstance(entry.getAttribute().getAttrValues().getObjectAt(0))
                  .getId()
                  .equals("1.2.840.10045.3.1.7"));
          Assert.assertTrue(
              ASN1ObjectIdentifier.getInstance(entry.getAttribute().getAttrValues().getObjectAt(1))
                  .getId()
                  .equals("1.2.840.10045.3.1.8"));
        } else {
          throw new Exception("unexpected attribute");
        }
      }
    }
  }

  @Test
  public void testCheckedException() throws Exception {
    thrown.expect(RegistrarException.class);

    String jsonStr =
        "[{\"1.2.840.10045.2.1\" : [\"1.2.840.10045.3.1.7\", \"1.2.840.10045.3.1.8\"]}, []]";
    try (InputStream in = new ByteArrayInputStream(jsonStr.getBytes())) {
      CSRAttributes attr = new CSRAttributes(in);
    }
  }
}
