/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.certificates;

import java.io.IOException;
import java.io.PrintStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.cesecore.util.Base64;

/**
 *
 */
public class CertificateToolsBase {
    private static Logger log = Logger.getLogger(CertificateToolsBase.class);

    /** Write the supplied bytes to the printstream as Base64 using beginKey and endKey around it. */
    public static void writeAsPemEncoded(PrintStream printStream, byte[] unencodedData, String beginKey, String endKey) {
        printStream.println(beginKey);
        printStream.println(new String(Base64.encode(unencodedData)));
        printStream.println(endKey);
    }
    
    protected static ASN1Primitive getDerObjectFromByteArray(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try {
            return ASN1Primitive.fromByteArray(ASN1OctetString.getInstance(bytes).getOctets());
        } catch (IOException e) {
            throw new IllegalStateException("Caught an unexected IOException", e);
        }
    }
    
    /**
     * Generate a SHA1 fingerprint from a byte array containing a certificate
     * 
     * @param ba Byte array containing DER encoded Certificate or CRL.
     * 
     * @return Byte array containing SHA1 hash of DER encoded certificate.
     */
    public static byte[] generateSHA1Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            log.error("SHA1 algorithm not supported", nsae);
        }
        return null;
    } 

    /**
     * Generate a SHA256 fingerprint from a byte array containing a certificate
     * 
     * @param ba Byte array containing DER encoded Certificate or CRL.
     * 
     * @return Byte array containing SHA256 hash of DER encoded certificate.
     */
    public static byte[] generateSHA256Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            log.error("SHA-256 algorithm not supported", nsae);
        }
        return null;
    } 

    /**
     * Generate a MD5 fingerprint from a byte array containing a certificate
     * 
     * @param ba Byte array containing DER encoded Certificate.
     * 
     * @return Byte array containing MD5 hash of DER encoded certificate (raw binary hash).
     */
    public static byte[] generateMD5Fingerprint(byte[] ba) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            return md.digest(ba);
        } catch (NoSuchAlgorithmException nsae) {
            log.error("MD5 algorithm not supported", nsae);
        }

        return null;
    } 

}
