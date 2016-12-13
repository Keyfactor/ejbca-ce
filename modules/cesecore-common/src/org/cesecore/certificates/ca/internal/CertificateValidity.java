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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.CertTools;
import org.cesecore.util.SimpleTime;
import org.cesecore.util.ValidityDate;

/** Class used to construct validity times based on a range of different input parameters and configuration. 
 * 
 * @version $Id$
 */
public class CertificateValidity {

	/** Class logger. */
    private static final Logger log = Logger.getLogger(CertificateValidity.class);
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    /** Issuing certificates with 'notAfter' greater than this value throws an exception. */
    private static Date TOO_LATE_EXPIRE_DATE;
    static {
        final String value = CesecoreConfiguration.getCaTooLateExpireDate();
        try {
            TOO_LATE_EXPIRE_DATE = ValidityDate.parseCaLatestValidDateTime(value);
        } catch (Exception e) {
            final String newValue = ValidityDate.formatAsISO8601(new Date(Long.MAX_VALUE), ValidityDate.TIMEZONE_SERVER);
            TOO_LATE_EXPIRE_DATE = ValidityDate.parseCaLatestValidDateTime(newValue);
            log.warn("cesecore.properties ca.toolateexpiredate '" + value + "' could not be parsed Using default value '"+newValue+"'.", e);
        }
    }
    
    /** 
     * Validity offset in milliseconds (offset for the 'notBefore' value)
     * The default start date is set 10 minutes back to avoid some problems with unsynchronized clocks.
     */
    private static long DEFAULT_VALIDITY_OFFSET;
    static {
        final String value = CesecoreConfiguration.getCertificateValidityOffset();
        try {
            DEFAULT_VALIDITY_OFFSET = SimpleTime.getSecondsFormat().parseMillis( value);
        } catch (Exception e) {
            // Use old value for compatibility reasons!
            DEFAULT_VALIDITY_OFFSET = -10L * 60 * 1000;
            log.warn("cesecore.properties certificate.validityoffset '" + value + "' could not be parsed as relative time string. Using default value '-10m' = -60000ms", e);
        }
    }
    
    /**
     * Gets the default validity offset.
     * @return the offset as relative time.
     * @See {@link org.cesecore.util.SimpleTime SimpleTime}
     */
    public static final long getValidityOffset() {
        return DEFAULT_VALIDITY_OFFSET;
    }
    
    /**
     * Gets the maximum possible value for the certificates 'notAfter' value.
     * @return ISO8601 date
     */
    public static Date getToolLateExpireDate() {
        return TOO_LATE_EXPIRE_DATE;
    }
    
    /**
     * Sets the maximum possible value for the certificates 'notAfter' value. This method MUST NOT BE CALLED, except for unit testing.
     * @param date the date to set.
     */
    public static void setTooLateExpireDate(final Date date) {
        TOO_LATE_EXPIRE_DATE = date;
    }
    
    /** The certificates 'notAfter' value. */
    private Date lastDate;

    /** The certificates 'notBefore' value. */
    private Date firstDate;
   
    public CertificateValidity(final EndEntityInformation subject, final CertificateProfile certProfile, 
            final Date notBefore, final Date notAfter, final Certificate cacert, final boolean isRootCA) throws IllegalValidityException {
        this(new Date(), subject, certProfile, notBefore, notAfter, cacert, isRootCA);
    }
   
    /** Constructor that injects the reference point (now). This constructor mainly is used for unit testing. */
	public CertificateValidity(Date now, final EndEntityInformation subject, final CertificateProfile certProfile, 
			final Date notBefore, final Date notAfter, final Certificate cacert, final boolean isRootCA) throws IllegalValidityException {
		if (log.isDebugEnabled()) {
		    log.debug("Requested notBefore: "+notBefore);
			log.debug("Requested notAfter: "+notAfter);
			if (null != subject.getExtendedinformation()) {
			    log.debug("End entity extended information 'notBefore': "+subject.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
			}
			if (null != subject.getExtendedinformation()) {
                log.debug("End entity extended information 'notAfter': "+subject.getExtendedinformation().getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
            }
			log.debug("Default validty offset: "+DEFAULT_VALIDITY_OFFSET);
			log.debug("Certificate profile validty: "+certProfile.getEncodedValidity());
			log.debug("Certificate profile use validty offset: "+certProfile.getUseCertificateValidityOffset());
			log.debug("Certificate profile validty offset: "+certProfile.getCertificateValidityOffset());
			log.debug("Certificate profile use expiration restrictions for weekdays: "+certProfile.getUseExpirationRestrictionForWeekdays());
			log.debug("Certificate profile expiration restrictions weekdays: "+certProfile.getExpirationRestrictionWeekdays());
			log.debug("Certificate profile expiration restrictions for weekdays before: "+certProfile.getExpirationRestrictionForWeekdaysExpireBefore());
		}
		if ( TOO_LATE_EXPIRE_DATE==null ) {
		    throw new IllegalStateException("ca.toolateexpiredate in cesecore.properties is not a valid date.");
		}
        
		// ECA-3554 add the offset
		now = getNowWithOffset(now, certProfile);
		if (log.isDebugEnabled()) {
		    log.debug("Using new start time including offset: " + now);
		}
         
		// Find out what start and end time to actually use..
        if (certProfile.getAllowValidityOverride()) {
            // First Priority has information supplied in Extended information object. This allows RA-users to set the time-span.
            // Second Priority has the information supplied in the method arguments
            firstDate = getExtendedInformationStartTime(now, subject);
            if (firstDate == null) {
            	firstDate = notBefore;
            }
            if ((lastDate = getExtendedInformationEndTime(now, subject)) == null) {
            	lastDate = notAfter;
            }    	
            if (log.isDebugEnabled()) {
                log.debug("Allow validity override, notBefore: "+firstDate);
                log.debug("Allow validity override, notAfter: "+lastDate);
            }
        }
        // Third priority: If nothing could be set by external information have the default  3 is default values
        if (firstDate == null) {
        	firstDate = now;
        }
        Date certProfileLastDate = new Date(getCertificateProfileValidtyEndDate(certProfile, firstDate));
        // Limit validity: ECA-5330 Apply expiration restriction for weekdays 
        if (certProfile.getUseExpirationRestrictionForWeekdays() && isRelativeTime(certProfile.getEncodedValidity())) {
            log.info("Applying expiration restrictions for weekdays: " + Arrays.asList(certProfile.getExpirationRestrictionWeekdays()));
            try {
                final Date newDate = ValidityDate.applyExpirationRestrictionForWeekdays(certProfileLastDate, 
                    certProfile.getExpirationRestrictionWeekdays(), certProfile.getExpirationRestrictionForWeekdaysExpireBefore());
                if (!firstDate.before(newDate)) {
                    log.warn("Expiration restriction of certificate profile could not be applied because it's before start date!");    
                } else if (!TOO_LATE_EXPIRE_DATE.after(newDate)) {
                    log.warn("Expiration restriction of certificate profile could not be applied because it's after latest possible end date!");
                } else {
                    certProfileLastDate = newDate;
                }
            } catch(Exception e) {
                log.warn("Expiration restriction of certificate profile could not be applied!");
            }
        }
        if (lastDate == null) {
        	lastDate = certProfileLastDate;
        }
        // Limit validity: Do not allow last date to be before first date
        if (lastDate.before(firstDate)) {
			log.info(intres.getLocalizedMessage("createcert.errorinvalidcausality",firstDate,lastDate));
        	Date tmp = lastDate;
        	lastDate = firstDate;
        	firstDate = tmp;
        }
		// Limit validity: We do not allow a certificate to be valid before the current date, i.e. not back dated start dates
        // Unless allowValidityOverride is set, then we allow everything
        // So this check is probably completely unneeded and can never be true
    	if (firstDate.before(now) && !certProfile.getAllowValidityOverride()) {
			log.error(intres.getLocalizedMessage("createcert.errorbeforecurrentdate",firstDate,subject.getUsername()));
    		firstDate = now;
    		// Update valid length from the profile since the starting point has changed
			certProfileLastDate = new Date(getCertificateProfileValidtyEndDate(certProfile, firstDate));
    		// Update lastDate if we use maximum validity
    	}
		// Limit validity: We do not allow a certificate to be valid after the the validity of the certificate profile
    	if (lastDate.after(certProfileLastDate)) {
    		log.info(intres.getLocalizedMessage("createcert.errorbeyondmaxvalidity",lastDate,subject.getUsername(),certProfileLastDate));
    		lastDate = certProfileLastDate;
    	}
		// Limit validity: We do not allow a certificate to be valid after the the validity of the CA (unless it's RootCA during renewal)
    	if (cacert != null && !isRootCA) {
    	    final Date caNotAfter = CertTools.getNotAfter(cacert);
    	    if (lastDate.after(caNotAfter)) {
    	        log.info(intres.getLocalizedMessage("createcert.limitingvalidity", lastDate.toString(), caNotAfter));
    	        lastDate = caNotAfter;
    	    }
    	}
    	// Limit validity: We do not allow a certificate to be valid before the the CA becomes valid (unless it's RootCA during renewal)
    	if (cacert != null && !isRootCA) {
    	    final Date caNotBefore = CertTools.getNotBefore(cacert);
    	    if (firstDate.before(caNotBefore)) {
    	        log.info(intres.getLocalizedMessage("createcert.limitingvaliditystart", firstDate.toString(), caNotBefore));
    	        firstDate = caNotBefore;
    	    }
        }
        if ( !lastDate.before(CertificateValidity.TOO_LATE_EXPIRE_DATE) ) {
        	String msg = intres.getLocalizedMessage("createcert.errorbeyondtoolateexpiredate", lastDate.toString(), CertificateValidity.TOO_LATE_EXPIRE_DATE.toString()); 
        	log.info(msg);
            throw new IllegalValidityException(msg);
        }
	}

	/** 
	 * Gets the certificates 'notAter' value.
	 * @return the 'notAfter' date.
	 */
	public Date getNotAfter() {
		return lastDate;
	}

	/** 
     * Gets the certificates 'notBefore' value.
     * @return the 'notBefore' date.
     */
	public Date getNotBefore() {
		return firstDate;
	}
	
	/**
     * Gets the validity end date for the certificate using the certificate profiles encoded validity.
     * @param profile the certificate profile
     * @param firstDate the start time.
     * @return the encoded validity.
     */
	@SuppressWarnings("deprecation")
    private long getCertificateProfileValidtyEndDate(CertificateProfile profile, Date firstDate) {
        final String encodedValidity = profile.getEncodedValidity();
        Date date = null;
        if (StringUtils.isNotBlank(encodedValidity)) {
            date = ValidityDate.getDate( encodedValidity, firstDate);
        } else {
            date = ValidityDate.getDateBeforeVersion661(profile.getValidity(),firstDate);
        }
        return date.getTime();
	}
	
	/**
	 * Offsets the certificates 'notBefore' (reference point) with the global offset or the offset of the certificate profile.
	 * @param now the reference point
	 * @param profile the certificate profile
	 * @return the offset reference point
	 */
	private Date getNowWithOffset(final Date now, final CertificateProfile profile) {
        Date result = null;
        if (profile.getUseCertificateValidityOffset()) {
            final String offset = profile.getCertificateValidityOffset();
            try {
                result = new Date(now.getTime() + SimpleTime.parseMillies(offset));
                if (log.isDebugEnabled()) {
                    log.debug( "Using validity offset by certificate profile: " + offset);
                }
            } catch(NumberFormatException e) {
                log.warn("Could not parse certificate validity offset " + offset + "; using default " + DEFAULT_VALIDITY_OFFSET);
            }
        } else {
            result = new Date(now.getTime() + DEFAULT_VALIDITY_OFFSET);
            if (log.isDebugEnabled()) {
                log.debug( "Using validity offset by cesecore.properties: " + SimpleTime.toString(DEFAULT_VALIDITY_OFFSET, SimpleTime.TYPE_DAYS));
            }
        }
        return result;
	}
	 
	/**
	 * Gets the start time by the extended entity information.
	 * @param now the reference point.
	 * @param subject the end entity information.
	 */
	private Date getExtendedInformationStartTime(final Date now, final EndEntityInformation subject) {
	    Date result = null;
        final ExtendedInformation extendedInformation = subject.getExtendedinformation();
        if (extendedInformation != null) {
            result = parseExtendedInformationEncodedValidity(now, extendedInformation.getCustomData(ExtendedInformation.CUSTOM_STARTTIME));
        }
        if (log.isDebugEnabled()) {
            log.debug("Using ExtendedInformationStartTime: " + result);
        }
        return result;
	}
	
	/**
     * Gets the end time by the extended entity information.
     * @param now the reference point.
     * @param subject the end entity information.
     */
	private Date getExtendedInformationEndTime(final Date now, final EndEntityInformation subject) {
        Date result = null;
        final ExtendedInformation extendedInformation = subject.getExtendedinformation();
        if (extendedInformation != null) {
            result = parseExtendedInformationEncodedValidity(now, extendedInformation.getCustomData(ExtendedInformation.CUSTOM_ENDTIME));
        }
        if (log.isDebugEnabled()) {
            log.debug("Using ExtendedInformationEndTime: " + result);
        }
        return result;
	}
	
	
	/**
	 * Checks that the PrivateKeyUsagePeriod of the certificate is valid at this time
	 * @param cacert

	 * @throws CAOfflineException if PrivateKeyUsagePeriod either is not valid yet or has expired, exception message gives details
	 */
	public static void checkPrivateKeyUsagePeriod(final X509Certificate cert) throws CAOfflineException {
	    checkPrivateKeyUsagePeriod(cert, new Date());
	}
	
    public static void checkPrivateKeyUsagePeriod(final X509Certificate cert, final Date checkDate) throws CAOfflineException {
        if (cert != null) {
            final PrivateKeyUsagePeriod pku = CertTools.getPrivateKeyUsagePeriod(cert);
            if (pku != null) {
                final ASN1GeneralizedTime notBefore = pku.getNotBefore();
                final Date pkuNotBefore;
                final Date pkuNotAfter;
                try {
                    if (notBefore == null) {
                        pkuNotBefore = null;
                    } else {
                        pkuNotBefore = notBefore.getDate();
                    }
                    if (log.isDebugEnabled()) {
                        log.debug("PrivateKeyUsagePeriod.notBefore is " + pkuNotBefore);
                    }
                    if (pkuNotBefore != null && checkDate.before(pkuNotBefore)) {
                        final String msg = intres.getLocalizedMessage("createcert.privatekeyusagenotvalid", pkuNotBefore.toString(), cert
                                .getSubjectDN().toString());
                        if (log.isDebugEnabled()) {
                            log.debug(msg);
                        }
                        throw new CAOfflineException(msg);
                    }
                    final ASN1GeneralizedTime notAfter = pku.getNotAfter();

                    if (notAfter == null) {
                        pkuNotAfter = null;
                    } else {
                        pkuNotAfter = notAfter.getDate();
                    }
                } catch (ParseException e) {
                    throw new IllegalStateException("Could not parse dates.", e);
                } 
                if (log.isDebugEnabled()) {
                    log.debug("PrivateKeyUsagePeriod.notAfter is " + pkuNotAfter);
                }
                if (pkuNotAfter != null && checkDate.after(pkuNotAfter)) {
                    final String msg = intres.getLocalizedMessage("createcert.privatekeyusageexpired", pkuNotAfter.toString(), cert.getSubjectDN().toString());
                    if (log.isDebugEnabled()) {
                        log.debug(msg);
                    }
                    throw new CAOfflineException(msg);
                }
            } else if (log.isDebugEnabled()) {
                log.debug("No PrivateKeyUsagePeriod available in certificate.");
            }
        } else if (log.isDebugEnabled()) {
            log.debug("No CA certificate available, not checking PrivateKeyUsagePeriod.");       
        }
    }
    
    /**
     * Checks if the encoded validity is an ISO8601 date or a relative time.
     * @param encodedValidity the validity
     * @return Boolean.TRUE if it is a relative time, Boolean.FALSE if it is an ISO8601 date, otherwise NULL.
     * @See {@link org.cesecore.util.ValidityDate ValidityDate}
     * @See {@link org.cesecore.util.SimpleTime SimpleTime}
     */
    private static final Boolean isRelativeTime(final String encodedValidity) {
        try {
            ValidityDate.parseAsIso8601(encodedValidity);
            return Boolean.FALSE;
        } catch(ParseException e) {
            // NOOP
        }
        try {
            SimpleTime.parseMillies(encodedValidity);
            return Boolean.TRUE;
        } catch(NumberFormatException nfe) {
            return null;
        }
    }
    
    /**
     * Parses the entity extended information start and end time format and offsets it with the reference point.
     * @param now the reference point
     * @param timeString the value in form of 'days:minutes:hours'
     * @return the parse value offset with now (reference point).
     */
    private static final Date parseExtendedInformationEncodedValidity(final Date now, final String timeString) {
        Date result = null;
        if (timeString != null) {
            if (timeString.matches("^\\d+:\\d?\\d:\\d?\\d$")) {
                final String[] endTimeArray = timeString.split(":");
                long relative = (Long.parseLong(endTimeArray[0])*24*60 
                              + Long.parseLong(endTimeArray[1])*60 
                              + Long.parseLong(endTimeArray[2])) * 60 * 1000;
                result = new Date(now.getTime() + relative);
            } else {
                try {
                    // Try parsing data as "yyyy-MM-dd HH:mm" assuming UTC
                    result = ValidityDate.parseAsUTC(timeString);
                } catch (ParseException e) {
                    log.error(intres.getLocalizedMessage("createcert.errorinvalidstarttime",timeString));
                }
            }
            if ((log.isDebugEnabled())) {
                log.debug("Time string by end entity extended Information: "+result);
            }
        }
        return result;
    }
}
