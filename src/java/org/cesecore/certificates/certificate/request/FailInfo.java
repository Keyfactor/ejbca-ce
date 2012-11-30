/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.certificate.request;

import java.io.Serializable;

import org.bouncycastle.asn1.cmp.PKIFailureInfo;

/**
 * Encapsulates the possible values for the failinfo part of a SCEP FAILURE response.
 *
 * Based on EJBCA version: FailInfo.java 8373 2009-11-30 14:07:00Z jeklund
 * 
 * @version $Id$
 */
public class FailInfo implements Serializable {

    private static final long serialVersionUID = 5198024740242161138L;

    /**
     * Unrecognized or unsupported algorithm ident
     */
    public static final FailInfo BAD_ALGORITHM = new FailInfo(0);

    /**
     * Integrity check failed
     */
    public static final FailInfo BAD_MESSAGE_CHECK = new FailInfo(1);

    /**
     * Transaction not permitted or supported
     */
    public static final FailInfo BAD_REQUEST = new FailInfo(2);

    /**
     * Message time field was not sufficiently close to the system time
     */
    public static final FailInfo BAD_TIME = new FailInfo(3);

    /**
     * No certificate could be identified matching the provided criteria
     */
    public static final FailInfo BAD_CERTIFICATE_ID = new FailInfo(4);
    /**
     * Request for wrong certificate authority
     */
    public static final FailInfo WRONG_AUTHORITY = new FailInfo(6);
    /**
     * Data incorrect, for example request for a non-existing user
     */
    public static final FailInfo INCORRECT_DATA = new FailInfo(7);
    /**
     * Verification of Proof of possession failed
     */
    public static final FailInfo BAD_POP = new FailInfo(9);
    /**
     * Not authorized
     */
    public static final FailInfo NOT_AUTHORIZED = new FailInfo(23);
    
    /** Array that converts our error codes to CMP BITString error codes. We use plain integer codes, which are
     * the same as positions in the CMP bit string
     * @see org.bouncycastle.asn1.cmp.PKIFailureInfo
     */
    private static int[] bcconversion = { PKIFailureInfo.badAlg,PKIFailureInfo.badMessageCheck,PKIFailureInfo.badRequest,PKIFailureInfo.badTime,PKIFailureInfo.badCertId
        ,PKIFailureInfo.badDataFormat,PKIFailureInfo.wrongAuthority,PKIFailureInfo.incorrectData,PKIFailureInfo.missingTimeStamp,PKIFailureInfo.badPOP
        ,PKIFailureInfo.certRevoked,PKIFailureInfo.certConfirmed,PKIFailureInfo.wrongIntegrity,PKIFailureInfo.badRecipientNonce,PKIFailureInfo.timeNotAvailable
        ,PKIFailureInfo.unacceptedPolicy,PKIFailureInfo.unacceptedExtension,PKIFailureInfo.addInfoNotAvailable,PKIFailureInfo.badSenderNonce,PKIFailureInfo.badCertTemplate
        ,PKIFailureInfo.signerNotTrusted,PKIFailureInfo.transactionIdInUse,PKIFailureInfo.unsupportedVersion,PKIFailureInfo.notAuthorized,PKIFailureInfo.systemUnavail
        ,PKIFailureInfo.systemFailure,PKIFailureInfo.duplicateCertReq};
    /**
     * The value actually encoded into the response message as the failinfo attribute
     */
    private final int value;

    private FailInfo(int value) {
        this.value = value;
    }

    /**
     * Gets the value embedded in the response message as a failinfo attribute
     * @return  the value to use
     */
    public String getValue() {
        return Integer.toString(value);
    }

    /** Returns the FailInfo value as an int that is the correct format for CMP, i.e. a DERBitString as specified in PKIFailureInfo.
     * @see org.bouncycastle.asn1.cmp.PKIFailureInfo
     * 
     * @return int
     */
    public int getCMPValue() {
        return bcconversion[value];
    }

    public boolean equals(Object o) {
        if (this == o) {
        	return true;
        }
        if (!(o instanceof FailInfo)) { 
        	return false;
        }
        final FailInfo scepResponseStatus = (FailInfo) o;
        if (value != scepResponseStatus.value) {
        	return false;
        }
        return true;
    }

    public int hashCode() {
        return value;
    }
    public String toString() {
    	return Integer.toString(value);
    }
}
