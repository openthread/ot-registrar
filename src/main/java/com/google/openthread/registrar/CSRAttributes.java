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

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.est.AttrOrOID;
import org.bouncycastle.asn1.pkcs.Attribute;

public class CSRAttributes {
  public static final String DEFAULT_FILE = "attributes.json";

  public CSRAttributes(String filename) throws RegistrarException {
    try (InputStream in = getClass().getClassLoader().getResourceAsStream(filename)) {
      attrAndOids = initAttrAndOids(new JsonParser().parse(new InputStreamReader(in)));
    } catch (IOException e) {
      throw new RegistrarException(e.getMessage());
    }
  }

  public CSRAttributes(InputStream in) throws RegistrarException {
    attrAndOids = initAttrAndOids(new JsonParser().parse(new InputStreamReader(in)));
  }

  public AttrOrOID[] getAttrAndOids() {
    return attrAndOids;
  }

  private AttrOrOID[] initAttrAndOids(final JsonElement element) throws RegistrarException {
    List<AttrOrOID> list = new ArrayList<>();
    try {
      JsonArray array = element.getAsJsonArray();
      for (JsonElement item : array) {
        if (item.isJsonObject()) {
          JsonObject attrs = item.getAsJsonObject();
          for (String type : attrs.keySet()) {
            JsonElement val = attrs.get(type);
            if (val.isJsonArray()) {
              list.add(new AttrOrOID(makeAttr(type, jsonArrayToStrings(val.getAsJsonArray()))));
            } else {
              list.add(new AttrOrOID(makeAttr(type, val.getAsString())));
            }
          }
        } else {
          String oid = item.getAsString();
          list.add(new AttrOrOID(makeOid(oid)));
        }
      }
    } catch (RuntimeException e) {
      throw new RegistrarException("attributes file error: " + e.getMessage());
    }

    return list.toArray(new AttrOrOID[list.size()]);
  }

  private static ASN1ObjectIdentifier makeOid(final String oid) {
    return new ASN1ObjectIdentifier(oid);
  }

  private static Attribute makeAttr(final String type, final String val) {
    return new Attribute(makeOid(type), new DERSet(makeOid(val)));
  }

  private static Attribute makeAttr(final String type, final List<String> vals) {
    ASN1EncodableVector v = new ASN1EncodableVector();
    for (String val : vals) {
      v.add(makeOid(val));
    }
    return new Attribute(makeOid(type), new DERSet(v));
  }

  private static List<String> jsonArrayToStrings(JsonArray arr) {
    List<String> ret = new ArrayList<>();
    for (JsonElement element : arr) {
      ret.add(element.getAsString());
    }
    return ret;
  }

  private AttrOrOID[] attrAndOids;
}
