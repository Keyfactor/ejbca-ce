package se.anatom.ejbca.hardtoken.hardtokenprofiles;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import se.anatom.ejbca.SecConst;


/**
 * Hard token profile with a goal to fulfill Swedish EID standard.
 * 
 * @version $Id: SwedishEIDProfile.java,v 1.1 2003-12-05 14:50:27 herrvendil Exp $
 */
public class SwedishEIDProfile extends EIDProfile {
		
	// Public Constants
	public static final int TYPE_SWEDISHEID = 1;
	
	public static final float LATEST_VERSION = 0;

    public static final int CERTUSAGE_SIGN    = 0;
	public static final int CERTUSAGE_AUTHENC = 1;
	
	public static final int PINTYPE_AUTHENC_SAME_AS_SIGN = 100;
			
	
	// Protected Constants
	protected static final int NUMBEROFCERTIFICATES = 2;
	
	
	// Private Constants
	public static final int[] AVAILABLEMINIMUMKEYLENGTHS = {1024};
		
	
	// Protected Fields
	private String[] pinstore = new String[NUMBEROFCERTIFICATES];
	private String[] pukstore = new String[NUMBEROFCERTIFICATES];
	
	private String[][] SUPPORTEDTOKENS = {{"TODO"}};
	
	
	
    // Default Values
    public SwedishEIDProfile() {
      super();
      
      data.put(TYPE, new Integer(TYPE_SWEDISHEID));
      
      ArrayList certprofileids = new ArrayList(NUMBEROFCERTIFICATES);
	  certprofileids.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN)); 
	  certprofileids.add(new Integer(SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC));
	  data.put(CERTIFICATEPROFILEID, certprofileids);
	  	  
	  ArrayList caids = new ArrayList(NUMBEROFCERTIFICATES);
	  caids.add(new Integer(0)); // Currently not used
	  caids.add(new Integer(0)); // Currently not used
	  data.put(CAID, caids);    
	  
	  ArrayList pintypes = new ArrayList(NUMBEROFCERTIFICATES);
	  pintypes.add(new Integer(PINTYPE_4DIGITS));
	  pintypes.add(new Integer(PINTYPE_4DIGITS));
	  data.put(PINTYPE, pintypes);
	  
	  ArrayList iskeyrecoverable = new ArrayList(NUMBEROFCERTIFICATES);
	  iskeyrecoverable.add(new Boolean(false));
	  iskeyrecoverable.add(new Boolean(false));
	  data.put(ISKEYRECOVERABLE, iskeyrecoverable);

	  ArrayList minimumkeylength = new ArrayList(NUMBEROFCERTIFICATES);
	  minimumkeylength.add(new Integer(1024));
	  minimumkeylength.add(new Integer(1024));
	  data.put(MINIMUMKEYLENGTH, minimumkeylength);	  

	  ArrayList keytypes = new ArrayList(NUMBEROFCERTIFICATES);
	  keytypes.add(KEYTYPE_RSA);
	  keytypes.add(KEYTYPE_RSA);
	  data.put(KEYTYPES, keytypes);
	  
	  // HERE
    }


	
	public int[] getAvailableMinimumKeyLengths(){
		return AVAILABLEMINIMUMKEYLENGTHS;
	}
	  				        

	/** 
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile#isTokenSupported(java.lang.String)
	 */
	public boolean isTokenSupported(String tokenidentificationstring) {		
		return this.isTokenSupported(SUPPORTEDTOKENS, tokenidentificationstring);
	}

	/* 
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile#getPIN(int, boolean)
	 */
	public String getPIN(int certusage, boolean regenerate){
		if(certusage == CERTUSAGE_AUTHENC && getPINType(certusage) == PINTYPE_AUTHENC_SAME_AS_SIGN)
		  return getPIN(pinstore,CERTUSAGE_SIGN, getPINType(CERTUSAGE_SIGN), false);
		return getPIN(pinstore,certusage, getPINType(certusage),regenerate);
	}

	/* 
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile#getPUK(int, boolean)
	 */
	public String getPUK(int certusage, boolean regenerate) {		
		if(certusage == CERTUSAGE_AUTHENC && getPINType(certusage) == PINTYPE_AUTHENC_SAME_AS_SIGN)
		  return getPUK(pinstore,CERTUSAGE_SIGN, getPINType(CERTUSAGE_SIGN), false);
		return getPUK(pukstore,certusage, getPINType(certusage),regenerate);
	}


	/* 
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
	    SwedishEIDProfile clone = new SwedishEIDProfile();
	    HashMap clonedata = (HashMap) clone.saveData();
	    Iterator i = (data.keySet()).iterator();
	    while(i.hasNext()){
		  Object key = i.next();
		  clonedata.put(key, data.get(key));
	    }

	    clone.loadData(clonedata);

	    return clone;
    }

	/* 
	 * @see se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile#getLatestVersion()
	 */
	public float getLatestVersion() {
	  return LATEST_VERSION;
	}

	public void upgrade(){
	  if(LATEST_VERSION != getVersion()){
		  // New version of the class, upgrade
	    super.upgrade();
	  }   
	}    
}
