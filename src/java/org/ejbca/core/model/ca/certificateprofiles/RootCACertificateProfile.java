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
 
package org.ejbca.core.model.ca.certificateprofiles;


/**
 * RootCACertificateProfile is a class defining the fixed characteristics of a root ca certificate profile.
 *
 * @version $Id$
 */
public class RootCACertificateProfile extends CertificateProfile{

    // Public Constants

    public static final String CERTIFICATEPROFILENAME =  "ROOTCA";

    // Public Methods
    /** Creates a certificate with the characteristics of an end user. 
     * General options are set in the superclass's default contructor that is called automatically.
     * You can override the general options by defining them again with different parameters here.
     */
    public RootCACertificateProfile() {

      setType(TYPE_ROOTCA);
      setAllowValidityOverride(true);
      setUseKeyUsage(true);
      setKeyUsage(new boolean[9]);
      setKeyUsage(DIGITALSIGNATURE,true);
      setKeyUsage(KEYCERTSIGN,true);
      setKeyUsage(CRLSIGN,true);
      setKeyUsageCritical(true);
      setValidity(25*365+7);	// Default validity for this profile is 25 years including 6 or 7 leap days
      
    }

    // Public Methods.

    public void upgrade(){
    	if(Float.compare(getLatestVersion(), getVersion()) != 0) {
    		// New version of the class, upgrade
    		super.upgrade();  			      
    	}
    }
    // Private fields.
}
