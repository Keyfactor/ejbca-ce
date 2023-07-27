/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.validation;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.keys.KeyTools;

/**
 * @version $Id$
 *
 */
public class RocaBrokenKeyValidatorTest {

    private final String KNOWN_VULNERABLE_KEY = "-----BEGIN PUBLIC KEY-----\n" 
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEBqcWmh9uPsqMPgt/43aFU\n"
            + "wpHvJ7BLJeGFuKsgxMal9gSFn+We3lSgr3wOcoiACtcZO7cxpb8eEXDXocZpMNQe\n"
            + "o+sh3t97ivXUKpHDT3IEW5bv1XyxgjAd3MJpZ+VQjpq4iZhtV+g33+cPmfw3xJj0\n"
            + "PBfDubBkz3BEQ9egM+A6ghaXqr8w+ynufTOzdnllqJBY47OXVL06HAB9KKI7DPp5\n"
            + "+dcRrG5MS093sGNLHs1oWRrwPH1TtipfLZEWPU70+PJoMa5GHthexfeIxRI//BLI\n"
            + "dCD9z+odG0pSw1IYJPs5mDSHObYqmG2OdrIom8Lri8BtE4FHhRuDoHGD0hBVn5Bj\n" 
            + "IQIDAQAB\n" 
            + "-----END PUBLIC KEY-----\n";

    private final String KNOWN_GOOD_KEY = "-----BEGIN PUBLIC KEY-----\n" 
            + "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArHNuuo2dva/7s3wNTJ8O\n"
            + "jFcogDTlekhMBaJFcLYZMoDTgBKWZO2NcNX5GBBos4h8B4eahdG/BRGedPhFzcg/\n"
            + "G9bDJ2DltoXQ69fVjTdPohqgdDKJoDYXr5IuFKJbEzj9glVGje2UhyE2Y7XbgL5u\n"
            + "KZCRcnTVgXQPdbxnRSSUPweZhzz6CnoseRe3XqkSRfAFstkbTcAKmeMKIJ0PCL5e\n"
            + "TOVpWL79jLc9nDo6wmMMdyWU8G9K2tXlbRcNpDcaPebOgKbkVF43KgPDFTuGcP9t\n"
            + "c7TbRjMmaYqB9rOOwFNXRhOr2vkuCn/qGyucx2Oc26fk6Y+suNrPB7/w3pIaro6Z\n" 
            + "EQIDAQAB\n" 
            + "-----END PUBLIC KEY-----";

    /**
     * Run a test on a known bad key (from https://github.com/crocs-muni/roca/blob/master/roca/tests/data/csr05.pem)
     */
    @Test
    public void testKnownBadKey() throws NoSuchAlgorithmException, InvalidKeySpecException {        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(
                KeyTools.getBytesFromPEM(KNOWN_VULNERABLE_KEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey knownBadPublicKey = (RSAPublicKey) kf.generatePublic(spec);
        assertTrue("Known vulnerable public key was not caught", RocaBrokenKey.isAffected(knownBadPublicKey.getModulus()));
    }
    
    /**
     * Run a test on a known good key 
     */
    @Test
    public void testKnownGoodKey() throws NoSuchAlgorithmException, InvalidKeySpecException {        
        X509EncodedKeySpec spec = new X509EncodedKeySpec(
                KeyTools.getBytesFromPEM(KNOWN_GOOD_KEY, CertTools.BEGIN_PUBLIC_KEY, CertTools.END_PUBLIC_KEY));
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKey knownBadPublicKey = (RSAPublicKey) kf.generatePublic(spec);
        assertFalse("Known good public key was falsely caught", RocaBrokenKey.isAffected(knownBadPublicKey.getModulus()));
    }
}
