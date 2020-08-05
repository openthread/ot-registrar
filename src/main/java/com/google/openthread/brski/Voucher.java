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

import com.strategicgains.util.date.DateAdapter;
import com.strategicgains.util.date.TimestampAdapter;
import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class Voucher {

  public static final class Assertion {
    public static Assertion VERIFIED = new Assertion(0);
    public static Assertion LOGGED = new Assertion(1);
    public static Assertion PROXIMITY = new Assertion(2);

    private Assertion(final int val) {
      value = val;
    }

    public static Assertion newAssertion(int val) {
      switch (val) {
        case 0:
          return VERIFIED;
        case 1:
          return LOGGED;
        case 2:
          return PROXIMITY;
        default:
          throw new IllegalArgumentException("unexpect assertion value: " + val);
      }
    }

    public boolean equals(Assertion other) {
      return value == other.value;
    }

    public int getValue() {
      return value;
    }

    private final int value;
  }

  public Assertion assertion;

  public Date createdOn;

  public Boolean domainCertRevocationChecks;

  public Date expiresOn;

  public byte[] idevidIssuer;

  public Date lastRenewalDate;

  public byte[] nonce;

  /*
   * An X.509 v3 certificate structure, as specified by RFC 5280,
   * using Distinguished Encoding Rules (DER) encoding, as defined
   * in ITU-T X.690.
   * This certificate is used by a pledge to trust a Public Key
   * Infrastructure in order to verify a domain certificate
   * supplied to the pledge separately by the bootstrapping
   * protocol. The domain certificate MUST have this certificate
   * somewhere in its chain of certificates. This certificate
   * MAY be an end-entity certificate, including a self-signed
   * entity.
   */
  public byte[] pinnedDomainCert;

  /*
   * The pinned-domain-subject replaces the
   * pinned-domain-certificate in constrained uses of
   * the voucher. The pinned-domain-subject-public-key-info
   * is the Raw Public Key of the Registrar.
   * This field is encoded as specified in RFC7250, section 3.
   * The ECDSA algorithm MUST be supported.
   * The EdDSA algorithm as specified in
   * draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
   * Support for the DSA algorithm is not recommended.
   * Support for the RSA algorithm is a MAY.
   */
  public byte[] pinnedDomainSPKI;

  /*
   * If it is necessary to change a voucher, or re-sign and
   * forward a voucher that was previously provided along a
   * protocol path, then the previously signed voucher SHOULD be
   * included in this field.
   * For example, a pledge might sign a proximity voucher, which
   * an intermediate registrar then re-signs to make its own
   * proximity assertion. This is a simple mechanism for a
   * chain of trusted parties to change a voucher, while
   * maintaining the prior signature information.
   * The pledge MUST ignore all prior voucher information when
   * accepting a voucher for imprinting. Other parties MAY
   * examine the prior signed voucher information for the
   * purposes of policy decisions. For example this information
   * could be useful to a MASA to determine that both pledge and
   * registrar agree on proximity assertions. The MASA SHOULD
   * remove all prior-signed-voucher-request information when
   * signing a voucher for imprinting so as to minimize the
   * final voucher size.
   */
  public byte[] priorSignedVoucherRequest;

  /*
   * An X.509 v3 certificate structure as specified by RFC 5280,
   * Section 4 encoded using the ASN.1 distinguished encoding
   * rules (DER), as specified in ITU-T X.690.
   * The first certificate in the Registrar TLS server
   * certificate_list sequence (see [RFC5246]) presented by
   * the Registrar to the Pledge. This MUST be populated in a
   * Pledge’s voucher request if the proximity assertion is
   * populated.
   */
  public byte[] proximityRegistrarCert;

  /*
   * The proximity-registrar-subject-public-key-info replaces
   * the proximit-registrar-cert in constrained uses of
   * the voucher-request.
   * The proximity-registrar-subject-public-key-info is the
   * Raw Public Key of the Registrar. This field is encoded
   * as specified in RFC7250, section 3.
   * The ECDSA algorithm MUST be supported.
   * The EdDSA algorithm as specified in
   * draft-ietf-tls-rfc4492bis-17 SHOULD be supported.
   * Support for the DSA algorithm is not recommended.
   * Support for the RSA algorithm is a MAY.
   */
  public byte[] proximityRegistrarSPKI;

  public String serialNumber;

  public static final String VOUCHER = "ietf-voucher:voucher";

  public static final String VOUCHER_REQUEST = "ietf-request-voucher:voucher";

  public static final String ASSERTION = "assertion";

  public static final String CREATED_ON = "created-on";

  public static final String DOMAIN_CERT_REVOCATION_CHECKS = "domain-cert-revocation-checks";

  public static final String EXPIRES_ON = "expires-on";

  public static final String IDEVID_ISSUER = "issuer";

  public static final String LAST_RENEWAL_DATE = "last-renewal-date";

  public static final String NONCE = "nonce";

  public static final String PINNED_DOMAIN_CERT = "pinned-domain-cert";

  public static final String PINNED_SHA256_DOMAIN_SPKI = "pinned-sha256-of-subject-public-key-info";

  public static final String PINNED_DOMAIN_SPKI = "pinned-domain-subject-public-key-info";

  public static final String PRIOR_SIGNED_VOUCHER_REQUEST = "prior-signed-voucher-request";

  public static final String PROXIMITY_REGISTRAR_CERT = "proximity-registrar-cert";

  public static final String SHA256_REGISTRAR_SPKI =
      "mity-registrar-sha256-of-subject-public-key-info";

  public static final String PROXIMITY_REGISTRAR_SPKI =
      "proximity-registrar-subject-public-key-info";

  public static final String SERIAL_NUMBER = "serial-number";

  public static final int VOUCHER_SID = 2451; // 1001104;

  public static final int VOUCHER_REQUEST_SID = 2501; // 1001154;

  public boolean validate() {
    if (assertion == null
        || createdOn == null
        || serialNumber == null
        || pinnedDomainCert == null) {
      return false;
    }
    if (expiresOn != null && nonce != null) {
      return false;
    }
    if (lastRenewalDate != null && expiresOn == null) {
      return false;
    }
    return true;
  }

  public String getName() {
    return VOUCHER;
  }

  public Object getKey(String item) {
    if (sidMap == null) {
      return getKeyName(item);
    }
    Integer sid = getKeySID(item);
    if (sid == null) {
      return null;
    }
    // FIXME(wgtdkp): how to determine if using sid diff ?
    if (sid.equals(VOUCHER_SID) || sid.equals(VOUCHER_REQUEST_SID)) {
      return sid;
    }
    return sid - (sidMap == voucherSIDMap ? VOUCHER_SID : VOUCHER_REQUEST_SID);
  }

  /** The Internet Date/Time Format (ref: ISO8601, section 5.6 RFC 3339) */
  public static String dateToYoungFormat(Date date) {
    DateAdapter adapter = new TimestampAdapter();
    return adapter.format(date);
  }

  public static Date dateFromYoungFormat(String young) throws ParseException {
    DateAdapter adapter = new TimestampAdapter();
    return adapter.parse(young);
  }

  protected Integer getKeySID(String item) {
    return sidMap.get(item);
  }

  protected String getKeyName(String item) {
    return item;
  }

  protected static final Map<String, Integer> voucherRequestSIDMap =
      new HashMap<String, Integer>() {
        {
          put(VOUCHER_REQUEST, VOUCHER_REQUEST_SID);
          put(ASSERTION, get(VOUCHER_REQUEST) + 1);
          put(CREATED_ON, get(VOUCHER_REQUEST) + 2);
          put(DOMAIN_CERT_REVOCATION_CHECKS, get(VOUCHER_REQUEST) + 3);
          put(EXPIRES_ON, get(VOUCHER_REQUEST) + 4);
          put(IDEVID_ISSUER, get(VOUCHER_REQUEST) + 5);
          put(LAST_RENEWAL_DATE, get(VOUCHER_REQUEST) + 6);
          put(NONCE, get(VOUCHER_REQUEST) + 7);
          put(PINNED_DOMAIN_CERT, get(VOUCHER_REQUEST) + 8);
          put(PRIOR_SIGNED_VOUCHER_REQUEST, get(VOUCHER_REQUEST) + 9);
          // put(PROXIMITY_REGISTRAR_CERT, get(VOUCHER_REQUEST) + 10);
          put(SHA256_REGISTRAR_SPKI, get(VOUCHER_REQUEST) + 11);
          put(PROXIMITY_REGISTRAR_SPKI, get(VOUCHER_REQUEST) + 12);
          put(SERIAL_NUMBER, get(VOUCHER_REQUEST) + 13);
        }
      };

  protected static final Map<String, Integer> voucherSIDMap =
      new HashMap<String, Integer>() {
        {
          put(VOUCHER, VOUCHER_SID);
          put(ASSERTION, get(VOUCHER) + 1);
          put(CREATED_ON, get(VOUCHER) + 2);
          put(DOMAIN_CERT_REVOCATION_CHECKS, get(VOUCHER) + 3);
          put(EXPIRES_ON, get(VOUCHER) + 4);
          put(IDEVID_ISSUER, get(VOUCHER) + 5);
          put(LAST_RENEWAL_DATE, get(VOUCHER) + 6);
          put(NONCE, get(VOUCHER) + 7);
          put(PINNED_DOMAIN_CERT, get(VOUCHER) + 8);
          put(PINNED_DOMAIN_SPKI, get(VOUCHER) + 9);
          put(PINNED_SHA256_DOMAIN_SPKI, get(VOUCHER) + 10);
          put(SERIAL_NUMBER, get(VOUCHER) + 11);
        }
      };

  protected Map<String, Integer> sidMap = null;
}
