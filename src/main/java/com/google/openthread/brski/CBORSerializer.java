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

package com.google.openthread.brski;

import com.upokecenter.cbor.CBORObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CBORSerializer implements VoucherSerializer {

  @Override
  public byte[] serialize(Voucher voucher) {
    return toCBOR(voucher).EncodeToBytes();
  }

  @Override
  public Voucher deserialize(byte[] data) {
    return fromCBOR(CBORObject.DecodeFromBytes(data));
  }

  public CBORObject toCBOR(Voucher voucher) {
    CBORObject cbor = CBORObject.NewMap();
    CBORObject container = CBORObject.NewMap();

    add(container, voucher.getKey(Voucher.ASSERTION), voucher.assertion.getValue());

    if (voucher.createdOn != null) {
      add(
          container,
          voucher.getKey(Voucher.CREATED_ON),
          Voucher.dateToYoungFormat(voucher.createdOn));
    }

    add(
        container,
        voucher.getKey(Voucher.DOMAIN_CERT_REVOCATION_CHECKS),
        voucher.domainCertRevocationChecks);

    if (voucher.expiresOn != null) {
      add(
          container,
          voucher.getKey(Voucher.EXPIRES_ON),
          Voucher.dateToYoungFormat(voucher.expiresOn));
    }

    add(container, voucher.getKey(Voucher.IDEVID_ISSUER), voucher.idevidIssuer);

    if (voucher.lastRenewalDate != null) {
      add(
          container,
          voucher.getKey(Voucher.LAST_RENEWAL_DATE),
          Voucher.dateToYoungFormat(voucher.lastRenewalDate));
    }

    add(container, voucher.getKey(Voucher.NONCE), voucher.nonce);

    add(container, voucher.getKey(Voucher.PINNED_DOMAIN_CERT), voucher.pinnedDomainCert);

    add(container, voucher.getKey(Voucher.PINNED_DOMAIN_SPKI), voucher.pinnedDomainSPKI);

    add(
        container,
        voucher.getKey(Voucher.PRIOR_SIGNED_VOUCHER_REQUEST),
        voucher.priorSignedVoucherRequest);

    add(
        container,
        voucher.getKey(Voucher.PROXIMITY_REGISTRAR_CERT),
        voucher.proximityRegistrarCert);

    add(
        container,
        voucher.getKey(Voucher.PROXIMITY_REGISTRAR_SPKI),
        voucher.proximityRegistrarSPKI);

    add(container, voucher.getKey(Voucher.SERIAL_NUMBER), voucher.serialNumber);

    cbor.Add(voucher.getKey(voucher.getName()), container);

    return cbor;
  }

  public Voucher fromCBOR(CBORObject cbor) {
    Voucher voucher = null;
    try {
      for (CBORObject key : cbor.getKeys()) {
        if (key.isIntegral()) {
          if (key.AsInt32() == Voucher.VOUCHER_SID) {
            voucher = new ConstrainedVoucher();
          } else if (key.AsInt32() == Voucher.VOUCHER_REQUEST_SID) {
            voucher = new ConstrainedVoucherRequest();
          } else {
            String msg =
                String.format(
                    "wrong voucher sid: %d, expecting %d for voucher and %d for voucher request",
                    key.AsInt32(), Voucher.VOUCHER_SID, Voucher.VOUCHER_REQUEST_SID);
            throw new Exception(msg);
          }
        } else if (key.AsString().equals(Voucher.VOUCHER)) {
          voucher = new Voucher();
        } else if (key.AsString().equals(Voucher.VOUCHER_REQUEST)) {
          voucher = new VoucherRequest();
        } else {
          String msg =
              String.format(
                  "wrong voucher : %s, expecting %s for voucher and %s for voucher request",
                  key.AsString(), Voucher.VOUCHER, Voucher.VOUCHER_REQUEST);
          throw new Exception(msg);
        }

        CBORObject container = cbor.get(key);
        CBORObject leaf;

        if ((leaf = get(container, voucher.getKey(Voucher.ASSERTION))) != null) {
          voucher.assertion = Voucher.Assertion.newAssertion(leaf.AsInt32());
        }

        if ((leaf = get(container, voucher.getKey(Voucher.CREATED_ON))) != null) {
          voucher.createdOn = Voucher.dateFromYoungFormat(leaf.AsString());
        }

        if ((leaf = get(container, voucher.getKey(Voucher.DOMAIN_CERT_REVOCATION_CHECKS)))
            != null) {
          voucher.domainCertRevocationChecks = leaf.AsBoolean();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.EXPIRES_ON))) != null) {
          voucher.expiresOn = Voucher.dateFromYoungFormat(leaf.AsString());
        }

        if ((leaf = get(container, voucher.getKey(Voucher.IDEVID_ISSUER))) != null) {
          voucher.idevidIssuer = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.LAST_RENEWAL_DATE))) != null) {
          voucher.lastRenewalDate = Voucher.dateFromYoungFormat(leaf.AsString());
        }

        if ((leaf = get(container, voucher.getKey(Voucher.NONCE))) != null) {
          voucher.nonce = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.PINNED_DOMAIN_CERT))) != null) {
          voucher.pinnedDomainCert = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.PINNED_DOMAIN_SPKI))) != null) {
          voucher.pinnedDomainSPKI = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.PRIOR_SIGNED_VOUCHER_REQUEST))) != null) {
          voucher.priorSignedVoucherRequest = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.PROXIMITY_REGISTRAR_CERT))) != null) {
          voucher.proximityRegistrarCert = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.PROXIMITY_REGISTRAR_SPKI))) != null) {
          voucher.proximityRegistrarSPKI = leaf.GetByteString();
        }

        if ((leaf = get(container, voucher.getKey(Voucher.SERIAL_NUMBER))) != null) {
          voucher.serialNumber = leaf.AsString();
        }

        // We process only one voucher
        break;
      }
    } catch (Exception e) {
      logger.error("bad voucher: " + e.getMessage());
      e.printStackTrace();
      return null;
    }

    return voucher;
  }

  protected void add(CBORObject c, Object key, Object val) {
    if (val != null) {
      c.Add(key, val);
    }
  }

  protected CBORObject get(CBORObject c, Object key) {
    return c.get(CBORObject.FromObject(key));
  }

  private static Logger logger = LoggerFactory.getLogger(CBORSerializer.class);
}
