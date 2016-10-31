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
package org.cesecore.certificates.ca.internal;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ValidityDate;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests calculation of certificate validity dates
 * 
 * @version $Id$
 *
 */
public class CertificateValidityTest {

	@Before
	public void setUp() throws Exception {
		CryptoProviderTools.installBCProviderIfNotAvailable();
    }

	@Test
    public void test01TestCertificateValidity() throws Exception {
        testBaseTestCertificateValidity("50d");
    }

	@Test
    public void test02TestCertificateValidity() throws Exception {
        final Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));
        cal.add(Calendar.DATE, 50);
        testBaseTestCertificateValidity(ValidityDate.formatAsISO8601(cal.getTime(), ValidityDate.TIMEZONE_SERVER));
    }
	
	@Test
	public void test03TestCheckPrivateKeyUsagePeriod() throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchAlgorithmException, SignatureException, IllegalStateException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException, CAOfflineException, ParseException {
	    final KeyPair pair = KeyTools.genKeys("512", "RSA");
	    /// A certificate without private key usage period
	    X509Certificate cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
	            AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, null, null, "BC");
	    // No private key usage period, should pass fine 
	    CertificateValidity.checkPrivateKeyUsagePeriod(cert);
        // A certificate with private key usage period notBefore == "now"
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, new Date(), null, "BC");
        // should pass fine 
        CertificateValidity.checkPrivateKeyUsagePeriod(cert);
        // A certificate with private key usage period notAfter == "now+1h"
        Calendar cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, 1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, null, cal.getTime(), "BC");
        // should pass fine 
        CertificateValidity.checkPrivateKeyUsagePeriod(cert);
        // A certificate with private key usage period notBefore == "now" and notAfter == "now+1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, 1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, new Date(), cal.getTime(), "BC");
        // should pass fine 
        CertificateValidity.checkPrivateKeyUsagePeriod(cert);
        // A certificate with private key usage period notBefore == "now+1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, 1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, cal.getTime(), null, "BC");
        try {
            CertificateValidity.checkPrivateKeyUsagePeriod(cert);
            fail("A certificate with private key usage period notBefore == now+1h should not be useful.");
        } catch (CAOfflineException e) {
            // NOPMD: should throw
        }
        // A certificate with private key usage period notAfter == "now-1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, -1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, null, cal.getTime(), "BC");
        try {
            CertificateValidity.checkPrivateKeyUsagePeriod(cert);
            fail("A certificate with private key usage period notAfter == now-1h should not be useful.");
        } catch (CAOfflineException e) {
            // NOPMD: should throw
        }
        // A certificate with private key usage period notBefore == "now+1h" and notAfter == "now-1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, -1);
        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.HOUR_OF_DAY, 1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, cal2.getTime(), cal.getTime(), "BC");
        try {
            CertificateValidity.checkPrivateKeyUsagePeriod(cert);
            fail("A certificate with private key usage period notBefore == now+1h and notAfter == now-1h should not be useful.");
        } catch (CAOfflineException e) {
            // NOPMD: should throw
        }
        // A certificate with private key usage period notBefore == "now-1h" and notAfter == "now-1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, -1);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.HOUR_OF_DAY, -1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, cal2.getTime(), cal.getTime(), "BC");
        try {
            CertificateValidity.checkPrivateKeyUsagePeriod(cert);
            fail("A certificate with private key usage period notBefore == now-1h and notAfter == now-1h should not be useful.");
        } catch (CAOfflineException e) {
            // NOPMD: should throw
        }
        // A certificate with private key usage period notBefore == "now+1h" and notAfter == "now+1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, 1);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.HOUR_OF_DAY, 1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, cal2.getTime(), cal.getTime(), "BC");
        try {
            CertificateValidity.checkPrivateKeyUsagePeriod(cert);
            fail("A certificate with private key usage period notBefore == now+1h and notAfter == now+1h should not be useful.");
        } catch (CAOfflineException e) {
            // NOPMD: should throw
        }
        // A certificate with private key usage period notBefore == "now-1h" and notAfter == "now+1h"
        cal = Calendar.getInstance();
        cal.add(Calendar.HOUR_OF_DAY, 1);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.HOUR_OF_DAY, -1);
        cert = CertTools.genSelfCertForPurpose("CN=CheckPK", 365, null, pair.getPrivate(), pair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.digitalSignature, cal2.getTime(), cal.getTime(), "BC");
        // Should work
        CertificateValidity.checkPrivateKeyUsagePeriod(cert);
	}
	
    private void testBaseTestCertificateValidity(String encodedValidity) throws Exception {

		KeyPair keys = KeyTools.genKeys("1024", "RSA");
		
		final Date caFrom = new Date();
		caFrom.setTime(caFrom.getTime() - 20L*(24L*60L*60L*1000L));
		final Date caTo = new Date();
		caTo.setTime(caTo.getTime() + 100L*(24L * 60L * 60L * 1000L));
		
    	X509Certificate cacert = CertTools.genSelfCertForPurpose("CN=dummy2", caFrom, caTo, null, keys.getPrivate(), keys.getPublic(),
    			AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.cRLSign|X509KeyUsage.keyCertSign,
    			null, null, "BC", true, null);

    	EndEntityInformation subject = new EndEntityInformation();

    	final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	cp.setEncodedValidity(encodedValidity);
    	cp.setUseExpirationRestrictionForWeekdays(false);
    	cp.setAllowValidityOverride(false);
    
    	// First see that when we don't have a specified time requested and validity override is not allowed, the end time should be ruled by the certificate profile.
    	
    	CertificateValidity cv = new CertificateValidity(subject, cp, null, null, cacert, false);
    	Date notBefore = cv.getNotBefore();
    	Date notAfter = cv.getNotAfter();
    	Date now = new Date();
        Calendar cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 49);
        Calendar cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 51);
    	assertTrue(notBefore.before(now));
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// See that a requested validity does not affect it
        Calendar requestNotBefore = Calendar.getInstance();
        requestNotBefore.add(Calendar.DAY_OF_MONTH, 2);
        Calendar requestNotAfter = Calendar.getInstance();
        requestNotAfter.add(Calendar.DAY_OF_MONTH, 25);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
    	assertTrue(notBefore.before(now));
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// Add extended information for the user and see that it does not affect it either
    	ExtendedInformation ei = new ExtendedInformation();
    	ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, "10:0:0"); // days:hours:minutes
    	ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, "30:0:0");
    	subject.setExtendedinformation(ei);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
    	assertTrue(notBefore.before(now));
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// Now allow validity override
    	cp.setAllowValidityOverride(true);
    	
    	// Now we should get what's in the EndEntityInformation extended information
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 9);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 11);
    	assertTrue(notBefore.after(cal1.getTime()));
    	assertTrue(notBefore.before(cal2.getTime()));
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 29);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 31);
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// Remove extended information from EndEntityInformation and we should get what we pass as parameters to CertificateValidity
    	subject.setExtendedinformation(null);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 1);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 3);
    	assertTrue(notBefore.after(cal1.getTime()));
    	assertTrue(notBefore.before(cal2.getTime()));
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 23);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 26);
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// Check that we can not supersede the certificate profile end time
        requestNotAfter = Calendar.getInstance();
        requestNotAfter.add(Calendar.DAY_OF_MONTH, 200);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal2 = Calendar.getInstance();
        // This will be counted in number of days since notBefore, and notBefore here is taken from requestNotBefore which is two, 
        // so we have to add 2 to certificate profile validity to get the resulting notAfter but not if certificate end is an 
        // absolute end date.
        if (isRelativeTime(encodedValidity)) {
            cal1.add(Calendar.DAY_OF_MONTH, 51);
            cal2.add(Calendar.DAY_OF_MONTH, 53);
        } else {
            cal1.add(Calendar.DAY_OF_MONTH, 49);
            cal2.add(Calendar.DAY_OF_MONTH, 51);
        }
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));

    	// Check that we can not supersede the CA end time
    	cp.setEncodedValidity(400 + SimpleTime.TYPE_DAYS);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
        // This will be the CA certificate's notAfter
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 99);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 101);
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));

    	// Unless it is a root CA, then we should be able to get a new validity after, to be able to update CA certificate
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, true);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 199);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 201);
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// Check that we can request a validity time before "now" using requested notBefore (in the CSR)
        requestNotBefore = Calendar.getInstance();
        requestNotBefore.add(Calendar.DAY_OF_MONTH, -10);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, -9);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, -11);
    	assertTrue(notBefore.before(cal1.getTime()));
    	assertTrue(notBefore.after(cal2.getTime()));
        // This will be the CA certificate's notAfter
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 99);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 101);
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));

        // Check that we can request a validity time before "now" using ExtendedInformation as well (set to 10 days before)
        ei = new ExtendedInformation();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, -10);
        ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, ValidityDate.formatAsUTC(cal1.getTime()));
        ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, "200:0:0");
        subject.setExtendedinformation(ei);
        cv = new CertificateValidity(subject, cp, null, null, cacert, false);
        notBefore = cv.getNotBefore();
        notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, -9);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, -11);
        assertTrue(notBefore.before(cal1.getTime()));
        assertTrue(notBefore.after(cal2.getTime()));
        // This will be the CA certificate's notAfter
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 99);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, 101);
        assertTrue(notAfter.after(cal1.getTime()));
        assertTrue(notAfter.before(cal2.getTime()));
        // See that it is not allowed when allowValidityOverride is set to false
        cp.setAllowValidityOverride(false);
        cv = new CertificateValidity(subject, cp, null, null, cacert, false);
        notBefore = cv.getNotBefore();
        notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 1);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, -1);
        assertTrue(notBefore.before(cal1.getTime()));
        assertTrue(notBefore.after(cal2.getTime()));
        subject.setExtendedinformation(null); // Reset after test
        cp.setAllowValidityOverride(true);
        
    	// Check that ca.toolateexpiredate setting in ejbca.properties is in effect
    	Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 5);
        CertificateValidity.setTooLateExpireDate(cal.getTime());
        boolean thrown = false;
        try {
            cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false);        	
        } catch (IllegalValidityException e) {
        	thrown = true;
        	//log.debug(e.getMessage());
        	String msg = e.getMessage();
        	// When running from within eclipse it will not have the correct internalresources.
        	if (!msg.contains("Requested expire date is not before the configured 'ca.toolateexpiredate'") && (!msg.equals("signsession.errorbeyondtoolateexpiredate"))) {
            	assertTrue(msg, false);        		
        	}
        }
        assertTrue(thrown);
        CertificateValidity.setTooLateExpireDate(new Date(Long.MAX_VALUE));
	}
    
    private final boolean isRelativeTime(String encodedValidity) {
        try {
            ValidityDate.parseAsIso8601(encodedValidity);
            return false;
        } catch(ParseException e) {
            // must be SimpleTime here
            return true;
        }
    }
}
