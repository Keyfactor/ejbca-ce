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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
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
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import org.apache.log4j.Logger;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

    /** Class logger */
    private static final Logger LOG = Logger.getLogger(CertificateValidityTest.class);
   
    private Date configToolLateExpireDate = CertificateValidity.getToolLateExpireDate();
    private KeyPair keyPair;
    private Date caFrom;
    private Date caTo; 
    private Date shortLivingCaFrom;
    private Date shortLivingCaTo; 
    private Date now;
    private Date absolulteTestDate;
    private Date tooLateExpireTestDate;
    private String relativeTimeString;
    private X509Certificate caCertificate;
    private X509Certificate shortLivingCaCertificate;
    
	@Before
	public void setUp() throws Exception {
		CryptoProviderTools.installBCProviderIfNotAvailable();
		// Everything from now on!
		now = new Date();
		keyPair = KeyTools.genKeys("1024", "RSA");
        CertificateValidity.setTooLateExpireDate(new SimpleDateFormat("yyyy-MM-dd hh:mm:ss").parse("2036-01-19 03:14:08"));
        configToolLateExpireDate = CertificateValidity.getToolLateExpireDate();
        tooLateExpireTestDate = new Date(configToolLateExpireDate.getTime() + 100L * SimpleTime.MILLISECONDS_PER_DAY);
		assertTrue("Too late expire test date exceeds it's configuration value", tooLateExpireTestDate.after(configToolLateExpireDate));
		// CA certificate for time nesting (validity from 20 days before to 100 days after)
		caFrom = new Date( now.getTime() - 120 * SimpleTime.MILLISECONDS_PER_DAY);
		caTo = new Date( now.getTime() + 500 * SimpleTime.MILLISECONDS_PER_DAY);
		assertTrue("CA start date is before end date.", caFrom.before(caTo));
        caCertificate = CertTools.genSelfCertForPurpose("CN=cacert", caFrom, caTo, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.cRLSign|X509KeyUsage.keyCertSign, null, null, "BC", true, null);
        shortLivingCaFrom = new Date( now.getTime() + 5 * SimpleTime.MILLISECONDS_PER_DAY);
        shortLivingCaTo = new Date( now.getTime() + 10 * SimpleTime.MILLISECONDS_PER_DAY);
        assertTrue("Short living CA start date is before end date.", shortLivingCaFrom.before(shortLivingCaTo));
        shortLivingCaCertificate = CertTools.genSelfCertForPurpose("CN=cacert", shortLivingCaFrom, shortLivingCaTo, null, keyPair.getPrivate(), keyPair.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.cRLSign|X509KeyUsage.keyCertSign, null, null, "BC", true, null);
        assertTrue("CA start date is before CA end date.", caFrom.before(caTo));
        absolulteTestDate = new Date( caTo.getTime() - 10 * SimpleTime.MILLISECONDS_PER_DAY); 
        assertTrue("Fix test end date '" + absolulteTestDate + "'is before CA end date '" + caTo + "'.", absolulteTestDate.before(caTo));
        relativeTimeString = "1y2mo3d4h5s";
        assertTrue("Realtive test time does not exceed CA end date time.", new Date(now.getTime() + SimpleTime.parseMillies(relativeTimeString)).before(caTo));
    }

	@Test
    public void test04TestAbsoluteValidityWithSecondsPrecision() throws Exception {
	    LOG.trace(">test04TestAbsoluteValidityWithSecondsPrecision");
	    final EndEntityInformation subject = new EndEntityInformation();
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CertificateValidity validity;
        profile.setEncodedValidity(ValidityDate.formatAsISO8601(absolulteTestDate, ValidityDate.TIMEZONE_SERVER));
        Date notBefore;
        Date notAfter;
        
        // A: Tests inside nested CA certificate validity.
        // 1. Test validity without offset in certificate profile: default offset by cesecore.properties with '-10m'.
        profile.setUseCertificateValidityOffset(false);
        profile.setUseExpirationRestrictionForWeekdays(false);
        profile.setAllowValidityOverride(false);
        validity = new CertificateValidity(now, subject, profile, null, null, caCertificate, false, false);
        notBefore = new Date(now.getTime() + CertificateValidity.getValidityOffset());
        notAfter = absolulteTestDate;
        assertTrue("1. NotBefore '"+validity.getNotBefore()+"'matches start date '"+notBefore+"'", validity.getNotBefore().equals(notBefore));
        assertTrue("1. NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'", equals(validity.getNotAfter(), notAfter));
        
        // 2. Test validity with offset in certificate profile: '-1mo-2d-3h-4m-5s'.
        profile.setUseCertificateValidityOffset(true);
        profile.setCertificateValidityOffset("-1mo-2d-3h-4m-5s");
        validity = new CertificateValidity(now, subject, profile, null, null, caCertificate, false, false);
        notBefore = new Date(now.getTime() + SimpleTime.parseMillies(profile.getCertificateValidityOffset()));
        notAfter = absolulteTestDate;
        assertTrue("2. NotBefore '"+validity.getNotBefore()+"'matches start date '"+notBefore+"'", validity.getNotBefore().getTime() == notBefore.getTime());
        assertTrue("2. NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'", equals(validity.getNotAfter(), notAfter));
        
        // 3. ECA-5330 Prove that expiration restrictions does not affect a fix date validity.
        profile.setUseExpirationRestrictionForWeekdays(true);
        GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTime(absolulteTestDate);
        profile.setExpirationRestrictionWeekday(calendar.get(Calendar.DAY_OF_WEEK), true);
        // now the end date caused by relative times must be rolled on day forward, but not with absolute times.
        profile.setExpirationRestrictionForWeekdaysExpireBefore(false);
        validity = new CertificateValidity(now, subject, profile, null, null, caCertificate, false, false);
        notBefore = new Date(now.getTime() + SimpleTime.parseMillies(profile.getCertificateValidityOffset()));
        notAfter = absolulteTestDate;
        assertTrue("3. NotBefore '"+validity.getNotBefore()+"'matches start date '"+notBefore+"'.", validity.getNotBefore().getTime() == notBefore.getTime());
        assertTrue("3. NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'.", equals(validity.getNotAfter(), notAfter));
        
        // 4.1 Overwrite start date with fixed date end entity information (which has first priority)
        // 5.1 Overwrite end date with fixed date end entity information (which has first priority)
        profile.setAllowValidityOverride(true);
        profile.setUseCertificateValidityOffset(true); // is overwritten by the extended information date!
        profile.setUseExpirationRestrictionForWeekdays(false); // otherwise it could overwrite the end date again!
        String extendedInformationStartDate = ValidityDate.formatAsUTC(now);
        String extendedInformationEndDate = ValidityDate.formatAsUTC(absolulteTestDate);
        ExtendedInformation extendedInformation = new ExtendedInformation();
        extendedInformation.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, extendedInformationStartDate);
        extendedInformation.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, extendedInformationEndDate);
        subject.setExtendedInformation(extendedInformation);
        Date methodParmameterStartDate = new Date( now.getTime() + 2L * SimpleTime.MILLISECONDS_PER_DAY);
        Date methodParmameterEndDate = new Date( absolulteTestDate.getTime() - 2L * SimpleTime.MILLISECONDS_PER_DAY);
        validity = new CertificateValidity(now, subject, profile, methodParmameterStartDate, methodParmameterEndDate, caCertificate, false, false);
        // seconds MUST be cut here!
        notBefore = ValidityDate.parseAsUTC(extendedInformationStartDate);
        notAfter = new Date((absolulteTestDate.getTime()/(60*1000))*60*1000);
        assertTrue("4.1 Start date '"+validity.getNotBefore()+"' was overwritten by extended information start date'"+notBefore+"'.", equals(validity.getNotBefore(), notBefore));
        assertTrue("5.1 NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'", equals(validity.getNotAfter(), notAfter));
        
        // 4.2 Overwrite start date by method parameter
        // 5.2 Overwrite end date by method parameter
        subject.getExtendedInformation().setCustomData(ExtendedInformation.CUSTOM_STARTTIME, null); // First priority -> set to null.
        subject.getExtendedInformation().setCustomData(ExtendedInformation.CUSTOM_ENDTIME, null); // First priority -> set to null.
        validity = new CertificateValidity(now, subject, profile, methodParmameterStartDate, methodParmameterEndDate, caCertificate, false, false);
        notBefore = methodParmameterStartDate;
        notAfter = methodParmameterEndDate;
        assertTrue("4.2 Start date '"+validity.getNotBefore()+"' was overwritten by method parameter start date'"+notBefore+"'.", equals(validity.getNotBefore(), notBefore));
        assertTrue("5.2 NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'", equals(validity.getNotAfter(), notAfter));
       
        // 6. Don't exceed CA too late expire date or an IllegalValidityException will be thrown! This is the last step!
        // There is a clause in certificate validity that prevents notAfter to be after the certificate profiles encodedValidity, so it MUST be set to a date after the date to test! 
        // Let away CA certificate to avoid time nesting.
        final Date exceededEndDate = new Date(tooLateExpireTestDate.getTime() + 2L * SimpleTime.MILLISECONDS_PER_DAY);
        try {
            profile.setEncodedValidity(ValidityDate.formatAsISO8601(new Date(tooLateExpireTestDate.getTime() + 4L * SimpleTime.MILLISECONDS_PER_DAY), ValidityDate.TIMEZONE_SERVER));
            validity = new CertificateValidity(now, subject, profile, null, exceededEndDate, null, false, false);
            fail("6. Exceeding the latest validity '"+tooLateExpireTestDate+"' with the end date '"+exceededEndDate+
                    "' MUST cause an IllegalValidityException! But may be the notAfter value was calculated wrong: '" + validity.getNotAfter() + "'");
        }
        catch(IllegalValidityException e) {
            // NOOP
        }
        LOG.trace("<test04TestAbsoluteValidityWithSecondsPrecision");
    }
	
	@Test
    public void test04TestTimeNestingWithSecondsPrecision() throws Exception {
        LOG.trace(">test04TestTimeNestingWithSecondsPrecision");
        final EndEntityInformation subject = new EndEntityInformation();
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CertificateValidity validity;
        profile.setEncodedValidity(ValidityDate.formatAsISO8601(absolulteTestDate, ValidityDate.TIMEZONE_SERVER));
        Date notBefore;
        Date notAfter;
        
        // B: Test against CA certificate time nesting (which is applied after start and end date was determined!).
        // 7. Time nest certificate start and end date
        // Enter the CA certificate again to enable time nesting.
        profile.setAllowValidityOverride(false);
        profile.setUseCertificateValidityOffset(false);
        profile.setUseExpirationRestrictionForWeekdays(false);
        final Date endDate = new Date(shortLivingCaTo.getTime() + 1L * SimpleTime.MILLISECONDS_PER_DAY);
        validity = new CertificateValidity(now, subject, profile, null, endDate, shortLivingCaCertificate, false, false);
        notBefore = shortLivingCaFrom;
        notAfter = shortLivingCaTo;
        assertTrue("7. NotBefore '"+validity.getNotBefore()+"'matches CA notBefore'"+notBefore+"'.", equals( validity.getNotBefore(), notBefore));
        assertTrue("7. NotAfter '"+validity.getNotAfter()+"' matches CA notAfter'"+notAfter+"'.", equals(validity.getNotAfter(), notAfter));
        LOG.trace("<test04TestTimeNestingWithSecondsPrecision");
	}
	
	@Test
    public void test05TestRelativeValidityWithSecondsPrecision() throws Exception {
	    LOG.trace(">test05TestRealtiveValidityWithSecondsPrecision");
        final EndEntityInformation subject = new EndEntityInformation();
        final CertificateProfile profile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        CertificateValidity validity;
        profile.setEncodedValidity("1mo");
        Date notBefore;
        Date notAfter;
        
        // A: Tests inside nested CA certificate validity.
        // 1. ECA-5141 Test relative time with seconds precision
        final String relativeTestTime = "7d8h9m10s";
        profile.setUseCertificateValidityOffset(false); // use default offset '-10m'
        profile.setUseExpirationRestrictionForWeekdays(false);
        profile.setEncodedValidity(relativeTestTime);
        validity = new CertificateValidity(now, subject, profile, null, null, caCertificate, false, false);
        notBefore = new Date(now.getTime() + CertificateValidity.getValidityOffset());
        notAfter = new Date(now.getTime() + CertificateValidity.getValidityOffset() + SimpleTime.parseMillies(relativeTestTime));
        assertTrue("1. NotBefore '"+validity.getNotBefore()+"'matches start date '"+notBefore+"'.", equals( validity.getNotBefore(), notBefore));
        assertTrue("1. NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'.", equals(validity.getNotAfter(), notAfter));
                
        // 2. ECA-5330 Expiration restrictions for a relative validity is applied during issuance.
        // 2.1 Roll forward ("but expire" -> "After")
        profile.setUseCertificateValidityOffset(false); // use default offset '-10m'
        profile.setUseExpirationRestrictionForWeekdays(true);
        GregorianCalendar calendar = new GregorianCalendar();
        calendar.setTime(notAfter);
        setExpirationRestrictionForWeekdays(profile, calendar.get(Calendar.DAY_OF_WEEK));
        // now the relative time validity end date must be rolled on day forward
        profile.setExpirationRestrictionForWeekdaysExpireBefore(false);
        validity = new CertificateValidity(now, subject, profile, null, null, caCertificate, false, false);
        notBefore = new Date(now.getTime() + CertificateValidity.getValidityOffset());
        notAfter = new Date(now.getTime() + CertificateValidity.getValidityOffset() + SimpleTime.parseMillies(relativeTestTime));
        calendar = new GregorianCalendar();
        calendar.setTime(notAfter);
        calendar.add(Calendar.DAY_OF_MONTH, 1); 
        notAfter = calendar.getTime();
        assertTrue("2.1 NotBefore '"+validity.getNotBefore()+"'matches start date '"+notBefore+"'.", validity.getNotBefore().getTime() == notBefore.getTime());
        assertTrue("2.1 NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'.", equals(validity.getNotAfter(), notAfter));
        
        // 2.2 Roll backward("but expire" -> "Before")
        profile.setExpirationRestrictionForWeekdaysExpireBefore(true);
        validity = new CertificateValidity(now, subject, profile, null, null, caCertificate, false, false);
        notBefore = new Date(now.getTime() + CertificateValidity.getValidityOffset());
        notAfter = new Date(now.getTime() + CertificateValidity.getValidityOffset() + SimpleTime.parseMillies(relativeTestTime));
        calendar = new GregorianCalendar();
        calendar.setTime(notAfter);
        calendar.add(Calendar.DAY_OF_MONTH, -1); 
        notAfter = calendar.getTime();
        assertTrue("3.1 NotBefore '"+validity.getNotBefore()+"'matches start date '"+notBefore+"'.", validity.getNotBefore().getTime() == notBefore.getTime());
        assertTrue("3.1 NotAfter '"+validity.getNotAfter()+"' matches end date '"+notAfter+"'.", equals(validity.getNotAfter(), notAfter));
        LOG.trace("<test05TestRealtiveValidityWithSecondsPrecision");
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
		final Date caFrom = new Date();
		caFrom.setTime(caFrom.getTime() - 20L*(24L*60L*60L*1000L));
		final Date caTo = new Date();
		caTo.setTime(caTo.getTime() + 100L*(24L * 60L * 60L * 1000L));
		
    	X509Certificate cacert = CertTools.genSelfCertForPurpose("CN=dummy2", caFrom, caTo, null, keyPair.getPrivate(), keyPair.getPublic(),
    			AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true, X509KeyUsage.cRLSign|X509KeyUsage.keyCertSign,
    			null, null, BouncyCastleProvider.PROVIDER_NAME, true, null);

        final EndEntityInformation subject = new EndEntityInformation();
    	final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
    	cp.setEncodedValidity(encodedValidity);
    	cp.setUseExpirationRestrictionForWeekdays(false);
    	cp.setAllowValidityOverride(false);
    
    	// First see that when we don't have a specified time requested and validity override is not allowed, the end time should be ruled by the certificate profile.
    	
    	CertificateValidity cv = new CertificateValidity(subject, cp, null, null, cacert, false, false);
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
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
    	assertTrue(notBefore.before(now));
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
    	// Add extended information for the user and see that it does not affect it either
    	ExtendedInformation ei = new ExtendedInformation();
    	ei.setCustomData(ExtendedInformation.CUSTOM_STARTTIME, "10:0:0"); // days:hours:minutes
    	ei.setCustomData(ExtendedInformation.CUSTOM_ENDTIME, "30:0:0");
    	subject.setExtendedInformation(ei);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
    	notBefore = cv.getNotBefore();
    	notAfter = cv.getNotAfter();
    	assertTrue(notBefore.before(now));
    	assertTrue(notAfter.after(cal1.getTime()));
    	assertTrue(notAfter.before(cal2.getTime()));
    	
        // Test link certificate and we should get what we pass as parameter to notAfter to CertificateValidity
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, true);
        notBefore = cv.getNotBefore();
        notAfter = cv.getNotAfter();
        assertTrue(notBefore.before(now));
        // Not after is the requested
        assertEquals(notAfter, requestNotAfter.getTime());
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
        notBefore = cv.getNotBefore();
        notAfter = cv.getNotAfter();
        assertTrue(notBefore.before(now));
        // Not after is not requested anymore
        assertFalse(notAfter.equals(requestNotAfter.getTime()));

    	// Now allow validity override
    	cp.setAllowValidityOverride(true);
    	
    	// Now we should get what's in the EndEntityInformation extended information
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
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
    	subject.setExtendedInformation(null);
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
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
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
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
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
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
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, true, false);
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
        cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);
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
        subject.setExtendedInformation(ei);
        cv = new CertificateValidity(subject, cp, null, null, cacert, false, false);
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
        cv = new CertificateValidity(subject, cp, null, null, cacert, false, false);
        notBefore = cv.getNotBefore();
        notAfter = cv.getNotAfter();
        cal1 = Calendar.getInstance();
        cal1.add(Calendar.DAY_OF_MONTH, 1);
        cal2 = Calendar.getInstance();
        cal2.add(Calendar.DAY_OF_MONTH, -1);
        assertTrue(notBefore.before(cal1.getTime()));
        assertTrue(notBefore.after(cal2.getTime()));
        subject.setExtendedInformation(null); // Reset after test
        cp.setAllowValidityOverride(true);
        
    	// Check that ca.toolateexpiredate setting in ejbca.properties is in effect
    	Calendar cal = Calendar.getInstance();
        cal.add(Calendar.DAY_OF_MONTH, 5);
        CertificateValidity.setTooLateExpireDate(cal.getTime());
        boolean thrown = false;
        try {
            cv = new CertificateValidity(subject, cp, requestNotBefore.getTime(), requestNotAfter.getTime(), cacert, false, false);        	
        } catch (IllegalValidityException e) {
        	thrown = true;
        	//log.debug(e.getMessage());
        	String msg = e.getMessage();
        	// When running from within eclipse it will not have the correct internalresources.
        	if (!msg.contains("Requested expire date is not before the configured 'ca.toolateexpiredate'") && (!msg.startsWith("createcert.errorbeyondtoolateexpiredate"))) {
            	assertTrue(msg, false);        		
        	}
        }
        assertTrue(thrown);
        CertificateValidity.setTooLateExpireDate(new Date(Long.MAX_VALUE));
        
	}
    
    /**
     * Returns true if the encoded validity given is no ISO8601 date.
     */
    private final boolean isRelativeTime(final String encodedValidity) {
        try {
            ValidityDate.parseAsIso8601(encodedValidity);
            return false;
        } catch(ParseException e) {
            // must be SimpleTime here
            return true;
        }
    }
    
    /** Compares the dates without milliseconds. */
    private final boolean equals(final Date leftSide, final Date rightSide) {
        return leftSide.getTime() / 1000 == rightSide.getTime() / 1000;
    }
    
    /** Creates a boolean[] for all weekdays, where the weekdays value given is set to true. */
    private final void setExpirationRestrictionForWeekdays(final CertificateProfile profile, final int weekday) {
        for (int i = 1; i<=7; i++) {
            profile.setExpirationRestrictionWeekday(i, weekday == i);
        }
    }
}
