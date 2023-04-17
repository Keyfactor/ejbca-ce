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
package org.ejbca.core.model;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;

import org.apache.log4j.Logger;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.RevocationReasons;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.BeforeClass;
import org.junit.Test;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import sun.reflect.ReflectionFactory;

/**
 * Unit tests for the CertSafePublisher
 * 
 * @version $Id$
 *
 */
public class CertSafePublisherTest {

    private static final Logger log = Logger.getLogger(CertSafePublisherTest.class);

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @Test
    public void testJSonSerialization() throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException,
            NoSuchMethodException, SecurityException, IllegalAccessException, IllegalArgumentException, InvocationTargetException, ParseException, InstantiationException {
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=PrimeKey,CN=testJSonSerialization", 365, null, keys.getPrivate(),
                keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        //We want to run this test without calling the constructor. Test code, so calling a sun-package is acceptable. 
        ReflectionFactory rf = ReflectionFactory.getReflectionFactory();
        Constructor<CustomPublisherContainer> objDef = CustomPublisherContainer.class.getDeclaredConstructor();
        Constructor<?> intConstr = rf.newConstructorForSerialization(CertSafePublisher.class, objDef);
        CertSafePublisher certSafePublisher = CertSafePublisher.class.cast(intConstr.newInstance());
        
        int status = CertificateConstants.CERT_REVOKED;
        int reason = RevocationReasons.KEYCOMPROMISE.getDatabaseValue();
        long date = 1541434399560L;
        Method getJSONString = CertSafePublisher.class.getDeclaredMethod("getJSONString", Certificate.class, int.class, int.class, long.class);
        getJSONString.setAccessible(true);
        //Certificate, Status, Revocation Reason, Revocation Date
        String jsonDump = (String) getJSONString.invoke(certSafePublisher, certificate, status, reason, date);
        JSONParser parser = new JSONParser();
        JSONObject jsonObject = (JSONObject) parser.parse(jsonDump);
        assertEquals("Revocation reason was not correctly JSON serialized", "keyCompromise",
                jsonObject.get(CertSafePublisher.JSON_REVOCATION_REASON));
        assertEquals("Certificate Status was not correctly JSON serialized", "revoked", jsonObject.get(CertSafePublisher.JSON_STATUS));
        // Check date
        final String actualDateString = (String) jsonObject.get(CertSafePublisher.JSON_REVOCATION_DATE);
        log.debug("Date string from JSON: " + actualDateString);
        final Date actualDate = parseDate(actualDateString);
        final Date expectedDate = parseDate("2018-11-05 17:13:19 CET");
        log.debug("Expected date in current timezone: " + expectedDate);
        log.debug("Actual date in current timezone:   " + actualDate);
        log.debug("Expected timestamp: " + expectedDate.getTime());
        log.debug("Actual timestamp:   " + actualDate.getTime());
        assertEquals("Revocation date was not correctly JSON serialized", expectedDate, actualDate);
        assertEquals("Certificate was not correctly JSON serialized", CertTools.getPemFromCertificate(certificate),
                jsonObject.get(CertSafePublisher.JSON_CERTIFICATE));
    }
    
    private Date parseDate(final String date) {
        final DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss z");
        try {
            return df.parse(date);
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

}
