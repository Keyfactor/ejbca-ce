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
import java.util.Date;

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
import org.cesecore.util.ValidityDate;

/** Class used to construct validity times based on a range of different input parameters and configuration. 
 * 
 * @version $Id$
 */
public class CertificateValidity {

    private static final Logger log = Logger.getLogger(CertificateValidity.class);
    
    /** 
     * Number of seconds before the issuing time the certificates notBefore date
     * will be set to.
     * The start date is set back ten minutes to avoid some problems with 
     * unsynchronized clocks.
     */
    public static final long SETBACKTIME = 10 * 60 * 1000;
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private Date lastDate;
    private Date firstDate;
    
    private static Date tooLateExpireDate = ValidityDate.parseCaLatestValidDateTime(CesecoreConfiguration.getCaTooLateExpireDate());

    /** Protected method so we can JUnit test this
     */
    protected static void setTooLateExpireDate(Date date) {
    	tooLateExpireDate = date;
    }
    
	public CertificateValidity(final EndEntityInformation subject, final CertificateProfile certProfile, 
			final Date notBefore, final Date notAfter, 
			final Certificate cacert, final boolean isRootCA) throws IllegalValidityException {
		if (log.isDebugEnabled()) {
			log.debug("Requested notBefore: "+notBefore);
			log.debug("Requested notAfter: "+notAfter);
		}
		if ( tooLateExpireDate==null ) {
		    throw new IllegalValidityException("ca.toolateexpiredate in ejbca.properties is not a valid date.");
		}
        // Set back start date ten minutes to avoid some problems with unsynchronized clocks.
        final Date now = new Date((new Date()).getTime() - SETBACKTIME);
        Date startTimeDate = null;
        Date endTimeDate = null;
        // Extract requested start and endtime from end endtity profile / user data
        final ExtendedInformation ei = subject.getExtendedinformation();
        if ( ei != null ) {
            final String eiStartTime = ei.getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
            final String eiEndTime = ei.getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
        	if ( eiStartTime != null ) {
        		if ( eiStartTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) {
        			final String[] startTimeArray = eiStartTime.split(":");
        			long relative = (Long.parseLong(startTimeArray[0])*24*60 + Long.parseLong(startTimeArray[1])*60 +
        					Long.parseLong(startTimeArray[2])) * 60 * 1000;
        			startTimeDate = new Date(now.getTime() + relative);
        		} else {
        			try {
        				// Try parsing data as "yyyy-MM-dd HH:mm" assuming UTC
        				startTimeDate = ValidityDate.parseAsUTC(eiStartTime);
        			} catch (ParseException e) {
        				log.error(intres.getLocalizedMessage("createcert.errorinvalidstarttime",eiStartTime));
        			}
        		}
    			if ( startTimeDate != null && startTimeDate.before(now)) {
    			    if ((log.isDebugEnabled())) {
    			        log.debug("Using custom start time, but it is before current date, will only be allowed if allowValidityOverride is true.");
    			    }
    			}
                if ((log.isDebugEnabled())) {
                    log.debug("Custom notBefore: "+startTimeDate);
                }
	        }
	        if ( eiEndTime != null ) {
        		if ( eiEndTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) {
        			final String[] endTimeArray = eiEndTime.split(":");
        			long relative = (Long.parseLong(endTimeArray[0])*24*60 + Long.parseLong(endTimeArray[1])*60 +
        					Long.parseLong(endTimeArray[2])) * 60 * 1000;
        			endTimeDate = new Date(now.getTime() + relative);
        		} else {
        			try {
        				// Try parsing data as "yyyy-MM-dd HH:mm" assuming UTC
        				endTimeDate = ValidityDate.parseAsUTC(eiEndTime);
        			} catch (ParseException e) {
        				log.error(intres.getLocalizedMessage("createcert.errorinvalidstarttime",eiEndTime));
        			}
        		}
                if ((log.isDebugEnabled())) {
                    log.debug("Custom notAfter: "+endTimeDate);
                }
	        }
        }
        // Find out what start and end time to actually use..
        if (certProfile.getAllowValidityOverride()) {
            // Prio 1 is infomation supplied in Extended information object. This allows RA-users to set the time-span.
            firstDate = startTimeDate;
            lastDate = endTimeDate;
            // Prio 2 is the information supplied in the arguments
            if (firstDate == null) {
            	firstDate = notBefore;
            }
            if (lastDate == null) {
            	lastDate = notAfter;
            }    	
            if (log.isDebugEnabled()) {
                log.debug("Allow validity override, notBefore: "+firstDate);
                log.debug("Allow validity override, notAfter: "+lastDate);
            }
        }
        // Prio 3 is default values
        if (firstDate == null) {
        	firstDate = now;
        }
        final long val = certProfile.getValidity();        
        Date certProfileLastDate = ValidityDate.getDate(val,firstDate);
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
			certProfileLastDate = ValidityDate.getDate(val,firstDate);
    		// Update lastDate if we use maximum validity
    		if (lastDate.equals(certProfileLastDate)) {
    			lastDate = certProfileLastDate;
    		}
    	}
		// Limit validity: We do not allow a certificate to be valid after the the validity of the certificate profile
    	if (lastDate.after(certProfileLastDate)) {
    		log.info(intres.getLocalizedMessage("createcert.errorbeyondmaxvalidity",lastDate,subject.getUsername(),certProfileLastDate));
    		lastDate = certProfileLastDate;
    	}
		// Limit validity: We do not allow a certificate to be valid after the the validity of the CA (unless it's RootCA during renewal)
        if (cacert != null && lastDate.after(CertTools.getNotAfter(cacert)) && !isRootCA) {
        	log.info(intres.getLocalizedMessage("createcert.limitingvalidity", lastDate.toString(), CertTools.getNotAfter(cacert)));
            lastDate = CertTools.getNotAfter(cacert);
        }
        // Limit validity: We do not allow a certificate to be valid before the the CA becomes valid (unless it's RootCA during renewal)
        if (cacert != null && firstDate.before(CertTools.getNotBefore(cacert)) && !isRootCA) {
            log.info(intres.getLocalizedMessage("createcert.limitingvaliditystart", firstDate.toString(), CertTools.getNotBefore(cacert)));
            firstDate = CertTools.getNotBefore(cacert);
        } 
        if ( !lastDate.before(CertificateValidity.tooLateExpireDate) ) {
        	String msg = intres.getLocalizedMessage("createcert.errorbeyondtoolateexpiredate", lastDate.toString(), CertificateValidity.tooLateExpireDate.toString()); 
        	log.info(msg);
            throw new IllegalValidityException(msg);
        }
	}

	public Date getNotAfter() {
		return lastDate;
	}

	public Date getNotBefore() {
		return firstDate;
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


}
