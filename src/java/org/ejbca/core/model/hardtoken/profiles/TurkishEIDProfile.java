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
 
package org.ejbca.core.model.hardtoken.profiles;


import java.util.ArrayList;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.hardtoken.HardTokenConstants;



/**
 * Hard token profile with a goal to fulfill Swedish EID standard.
 * 
 * @version $Id$
 */
public class TurkishEIDProfile extends EIDProfile {
		
	// Public Constants
	public static final int TYPE_TURKISHEID = HardTokenConstants.TOKENTYPE_TURKISHEID;
	
	public static final float LATEST_VERSION = 1;

    public static final int CERTUSAGE_SIGN    = 0;
	public static final int CERTUSAGE_AUTHENC = 1;
	
			
	
	// Protected Constants
	protected static final int NUMBEROFCERTIFICATES = 2;
	protected static final int NUMBEROFPINS = 1;
	
	
	// Private Constants
	public static final int[] AVAILABLEMINIMUMKEYLENGTHS = {1024, 2048};
		
	
	// Protected Fields

	
	
	
    // Default Values
    public TurkishEIDProfile() {
      super();
      init();      

    }

    private void init(){
        data.put(TYPE, new Integer(TYPE_TURKISHEID));
        
        ArrayList certprofileids = new ArrayList(NUMBEROFCERTIFICATES);
  	  certprofileids.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN)); 
  	  certprofileids.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
  	  data.put(CERTIFICATEPROFILEID, certprofileids);
  	  
  	  ArrayList certWritable = new ArrayList(NUMBEROFCERTIFICATES);
  	  certWritable.add(Boolean.FALSE);
  	  certWritable.add(Boolean.FALSE);
  	  data.put(CERTWRITABLE, certWritable);
  	  
  	  ArrayList caids = new ArrayList(NUMBEROFCERTIFICATES);
  	  caids.add(new Integer(CAID_USEUSERDEFINED)); 
  	  caids.add(new Integer(CAID_USEUSERDEFINED)); 
  	  data.put(CAID, caids);    
  	  
  	  ArrayList pintypes = new ArrayList(NUMBEROFPINS);
  	  pintypes.add(new Integer(PINTYPE_ASCII_NUMERIC));
  	  data.put(PINTYPE, pintypes);

  	  ArrayList minpinlength = new ArrayList(NUMBEROFPINS);
  	  minpinlength.add(new Integer(4));
  	  data.put(MINIMUMPINLENGTH, minpinlength);
  	  
  	  ArrayList iskeyrecoverable = new ArrayList(NUMBEROFCERTIFICATES);
  	  iskeyrecoverable.add(new Boolean(false));
  	  iskeyrecoverable.add(new Boolean(false));
  	  data.put(ISKEYRECOVERABLE, iskeyrecoverable);
  	  
  	    
  	  ArrayList reuseoldcertificate = new ArrayList(NUMBEROFCERTIFICATES);
  	  reuseoldcertificate.add(Boolean.FALSE);
  	  reuseoldcertificate.add(Boolean.FALSE);
  	  data.put(REUSEOLDCERTIFICATE, reuseoldcertificate);		    

  	  ArrayList minimumkeylength = new ArrayList(NUMBEROFCERTIFICATES);
  	  minimumkeylength.add(new Integer(1024));
  	  minimumkeylength.add(new Integer(1024));
  	  data.put(MINIMUMKEYLENGTH, minimumkeylength);	  

  	  ArrayList keytypes = new ArrayList(NUMBEROFCERTIFICATES);
  	  keytypes.add(KEYTYPE_RSA);
  	  keytypes.add(KEYTYPE_RSA);
  	  data.put(KEYTYPES, keytypes);
  	      	
    }

	
	public int[] getAvailableMinimumKeyLengths(){
		return AVAILABLEMINIMUMKEYLENGTHS;
	}
	  				        

	/** 
	 * @deprecated
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.HardTokenProfile#isTokenSupported(java.lang.String)
	 */
	public boolean isTokenSupported(String tokenidentificationstring) {		
		return false;
	}



	/* 
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.HardTokenProfile#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
	    TurkishEIDProfile clone = new TurkishEIDProfile();
	    super.clone(clone);

	    return clone;
    }

	/* 
	 * @see org.ejbca.core.model.hardtoken.hardtokenprofiles.HardTokenProfile#getLatestVersion()
	 */
	public float getLatestVersion() {
	  return LATEST_VERSION;
	}

	public void upgrade(){
		if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
			// New version of the class, upgrade
			super.upgrade();
			

			
			data.put(VERSION, new Float(LATEST_VERSION));
		}   
	}    
	
	/**
	 * @Override 
	 */
	public void reInit() {
		init();
	}
}
