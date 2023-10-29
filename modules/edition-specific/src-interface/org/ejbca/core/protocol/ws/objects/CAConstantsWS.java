/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ws.objects;

import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.catoken.CATokenConstants;

/**
 * Property keys for creation of CAs via WS.
 * 
 * @version $Id$
 */
public class CAConstantsWS {

    /**
     * The policy ID can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0' 
     * or objectID and cpsurl as '2.5.29.32.0 http://foo.bar.com/mycps.txt'. You can add multiple policies such as 
     * '2.5.29.32.0 http://foo.bar.com/mycps.txt 1.1.1.1.1 http://foo.bar.com/111cps.txt'.
     */
    public static final String POLICYID = "policyid";
    /** Key sequence which is important properties for CVC CAs */
    public static final String KEYSEQUENCE = "keysequence";
    public static final String KEYSEQUENCE_FORMAT = "keysequenceformat";
    /** When creating a CA signed by an external CA, if may be required (CVC CAs again) that the target CA is uploaded to create the request 
     * Set as plain Base64 encoded data of the certificate encoding:
     * KayValuePair kp = new KeyValuePair();
     * kp.setKey(CAConstantsWS.EXTERNAL_SIGNING_CA_CERTIFICATE);
     * kp.setValue(org.bouncycastle.util.encoders.Base64.toBase64String(cvcacert_se.getEncoded()));
     */
    public static final String EXTERNAL_SIGNING_CA_CERTIFICATE = "externalsigningcacert";
    
    /** Certificate signing key alias */
    public static final String CAKEYPURPOSE_CERTSIGN_STRING = CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING;
    /** Certificate Revocation List (CRL) signing key alias. Must be the same as the certificate signing key.  */
    public static final String CAKEYPURPOSE_CRLSIGN_STRING = CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING;
    /** Used for decryption of key recovery data. Must be an RSA key. */
    public static final String CAKEYPURPOSE_KEYENCRYPT_STRING = CATokenConstants.CAKEYPURPOSE_KEYENCRYPT_STRING;
    /** Test signing key. Used by health-check. */
    public static final String CAKEYPURPOSE_TESTKEY_STRING = CATokenConstants.CAKEYPURPOSE_TESTKEY_STRING;
    /** Default key. If any of the other aliases are not specified, this will be used in their place. Must be an RSA key if decryption key aliases are not specified.*/
    public static final String CAKEYPURPOSE_DEFAULT_STRING = CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING;
    
    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String INCLUDE_IN_HEALTH_CHECK = CAConstants.INCLUDE_IN_HEALTH_CHECK;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String REQUEST_PRE_PROCESSOR = CAConstants.REQUEST_PRE_PROCESSOR;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_USER_STORAGE = CAConstants.USE_USER_STORAGE;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String FINISH_USER = CAConstants.FINISH_USER;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String ALLOW_CHANGING_REVOCATION_REASON = CAConstants.ALLOW_CHANGING_REVOCATION_REASON;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_PARTITIONED_CRL = CAConstants.USE_PARTITIONED_CRL;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_LDAP_DN_ORDER = CAConstants.USE_LDAP_DN_ORDER;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_UTF8_POLICY_TEXT = CAConstants.USE_UTF8_POLICY_TEXT;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String ACCEPT_REVOCATION_NON_EXISTING_ENTRY = CAConstants.ACCEPT_REVOCATION_NON_EXISTING_ENTRY;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_CERTIFICATE_STORAGE = CAConstants.USE_CERTIFICATE_STORAGE;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_ENFORCE_KEY_RENEWAL = CAConstants.DO_ENFORCE_KEY_RENEWAL;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_STORE_OCSP_RESPONSES_ON_DEMAND = CAConstants.DO_STORE_OCSP_RESPONSES_ON_DEMAND;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String MS_CA_COMPATIBLE = CAConstants.MS_CA_COMPATIBLE;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_PRE_PRODUCE_OCSP_RESPONSES = CAConstants.DO_PRE_PRODUCE_OCSP_RESPONSES;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CA_SERIAL_NUMBER_OCTET_SIZE = CAConstants.CA_SERIAL_NUMBER_OCTET_SIZE;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_APPEND_ONLY_TABLE = CAConstants.USE_APPEND_ONLY_TABLE;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_OVERLAP_MILLISECONDS = CAConstants.CRL_OVERLAP_MILLISECONDS;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_NUMBER_USED = CAConstants.CRL_NUMBER_USED;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_ISSUANCE_INTERVAL_MILLISECONDS = CAConstants.CRL_ISSUANCE_INTERVAL_MILLISECONDS;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String CRL_EXPIRATION_PERIOD_MILLISECONDS = CAConstants.CRL_EXPIRATION_PERIOD_MILLISECONDS;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String POLICY_OIDS = CAConstants.POLICY_OIDS;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DEFAULT_OCSP_SERVICE_LOCATOR = CAConstants.DEFAULT_OCSP_SERVICE_LOCATOR;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String GENERATE_CRL_UPON_REVOCATION = CAConstants.GENERATE_CRL_UPON_REVOCATION;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_ENFORCE_UNIQUE_PUBLIC_KEYS = CAConstants.DO_ENFORCE_UNIQUE_PUBLIC_KEYS;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME = CAConstants.DO_ENFORCE_UNIQUE_DISTINGUISHED_NAME;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DELTA_CRL_MILLISECONDS = CAConstants.DELTA_CRL_MILLISECONDS;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String DEFAULT_CRL_DIST_POINT = CAConstants.DEFAULT_CRL_DIST_POINT;

    /** See <a href="https://doc.primekey.com/ejbca/ejbca-operations/ejbca-ca-concept-guide/certificate-authority-overview/ca-fields">CA Fields</a> in the EJBCA documentation */
    public static final String USE_AUTHORITY_KEY_IDENTIFIER = CAConstants.USE_AUTHORITY_KEY_IDENTIFIER;
}
