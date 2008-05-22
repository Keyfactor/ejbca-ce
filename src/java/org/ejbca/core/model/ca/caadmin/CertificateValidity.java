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
package org.ejbca.core.model.ca.caadmin;

import java.security.cert.Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.Date;
import java.util.Locale;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.ExtendedInformation;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.util.CertTools;

public class CertificateValidity {

    private static final Logger log = Logger.getLogger(CertificateValidity.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private Date lastDate;
    private Date firstDate;
    
	public CertificateValidity(UserDataVO subject, CertificateProfile certProfile, 
			Date notBefore, Date notAfter, 
			Certificate cacert, boolean isRootCA) {
        // Set back start date ten minutes to avoid some problems with unsynchronized clocks.
        Date now = new Date((new Date()).getTime() - 10 * 60 * 1000);
		Date startTimeDate = null; 
		Date endTimeDate = null; 
        // Extract requested start and endtime from end endtity profile / user data
        ExtendedInformation ei = subject.getExtendedinformation();
        if ( ei != null ) {
            String eiStartTime = ei.getCustomData(EndEntityProfile.STARTTIME);
	        String eiEndTime = ei.getCustomData(EndEntityProfile.ENDTIME);
        	if ( eiStartTime != null ) {
        		if ( eiStartTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) {
        			String[] startTimeArray = eiStartTime.split(":");
        			long relative = (Long.parseLong(startTimeArray[0])*24*60 + Long.parseLong(startTimeArray[1])*60 +
        					Long.parseLong(startTimeArray[2])) * 60 * 1000;
        			startTimeDate = new Date(now.getTime() + relative);
        		} else {
        			try {
        				startTimeDate = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).parse(eiStartTime);
        			} catch (ParseException e) {
        				log.error(intres.getLocalizedMessage("signsession.errorinvalidstarttime",eiStartTime));
        			}
        		}
    			if ( startTimeDate != null && startTimeDate.before(now)) {
                	startTimeDate = now;
    			}
	        }
	        if ( eiEndTime != null ) {
        		if ( eiEndTime.matches("^\\d+:\\d?\\d:\\d?\\d$") ) {
        			String[] endTimeArray = eiEndTime.split(":");
        			long relative = (Long.parseLong(endTimeArray[0])*24*60 + Long.parseLong(endTimeArray[1])*60 +
        					Long.parseLong(endTimeArray[2])) * 60 * 1000;
        			endTimeDate = new Date(now.getTime() + relative);
        		} else {
        			try {
        				endTimeDate = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US).parse(eiEndTime);
        			} catch (ParseException e) {
        				log.error(intres.getLocalizedMessage("signsession.errorinvalidstarttime",eiEndTime));
        			}
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
        }
        // Prio 3 is default values
        if (firstDate == null) {
        	firstDate = now;
        }
        long val = certProfile.getValidity();        
        Date certProfileLastDate = new Date(firstDate.getTime() + ( val * 24 * 60 * 60 * 1000));
        if (lastDate == null) {
        	lastDate = certProfileLastDate;
        }
        // Limit validity: Do not allow last date to be before first date
        if (!lastDate.after(firstDate)) {
			log.error(intres.getLocalizedMessage("signsession.errorinvalidcausality",firstDate,lastDate));
        	Date tmp = lastDate;
        	lastDate = firstDate;
        	firstDate = tmp;
        }
		// Limit validity: We do not allow a certificate to be valid before the current date, i.e. not backdated start dates
    	if (firstDate.before(now)) {
			log.error(intres.getLocalizedMessage("signsession.errorbeforecurrentdate",firstDate,subject.getUsername()));
    		firstDate = now;
    		// Update valid length from the profile since the starting point has changed
			certProfileLastDate = new Date(firstDate.getTime() + ( val * 24 * 60 * 60 * 1000));
    		// Update lastDate if we use maximum validity
    		if (lastDate.equals(certProfileLastDate)) {
    			lastDate = certProfileLastDate;
    		}
    	}
		// Limit validity: We do not allow a certificate to be valid after the the validity of the certificate profile
    	if (lastDate.after(certProfileLastDate)) {
    		log.error(intres.getLocalizedMessage("signsession.errorbeyondmaxvalidity",lastDate,subject.getUsername(),certProfileLastDate));
    		lastDate = certProfileLastDate;
    	}
		// Limit validity: We do not allow a certificate to be valid after the the validity of the CA (unless it's RootCA during renewal)
        if (cacert != null && lastDate.after(CertTools.getNotAfter(cacert)) && !isRootCA) {
        	log.info(intres.getLocalizedMessage("signsession.limitingvalidity", lastDate.toString(), CertTools.getNotAfter(cacert)));
            lastDate = CertTools.getNotAfter(cacert);
        }            
		
	}

	public Date getNotAfter() {
		return lastDate;
	}

	public Date getNotBefore() {
		return firstDate;
	}
}
