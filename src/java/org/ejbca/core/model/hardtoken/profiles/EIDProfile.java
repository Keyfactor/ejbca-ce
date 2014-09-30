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
 
package org.ejbca.core.model.hardtoken.profiles;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.cesecore.certificates.ca.CAInfo;
import org.ejbca.core.model.SecConst;




/**
 * EIDProfile is a basic class that should be inherited by all types
 * of eidprofiles in the system.
 *  
 *
 * @version $Id$
 */
public abstract class EIDProfile extends HardTokenProfileWithAdressLabel {
	
	private static final long serialVersionUID = 5516097629038242905L;

    public static final String KEYTYPE_RSA = "RSA";
	
	public static final int CAID_USEUSERDEFINED = SecConst.CAID_USEUSERDEFINED;
	
	// Protected Constants
	protected static final String CERTIFICATEPROFILEID           = "certificateprofileid";
	protected static final String CAID                           = "caid";	
	protected static final String ISKEYRECOVERABLE               = "iskeyrecoverable";
	protected static final String REUSEOLDCERTIFICATE            = "reuseoldcertificate";
	protected static final String MINIMUMKEYLENGTH               = "minimunkeylength";
	protected static final String KEYTYPES                       = "keytypes";
	protected static final String CERTWRITABLE                   = "certwritable";

  
			
    // Default Values
    public EIDProfile() {
      super();
            
    }

    // Public Methods
    /**
     * Indicates which certificate profileid that should be requested when
     * generating certificate of given certusage.
     * 
     * @param certusage should be one of the CERTUSAGE_ constants.
     * @return The certificate profile id that should be used.
     */
    @SuppressWarnings("unchecked")
    public int getCertificateProfileId(int certusage){return ((Integer) ((List<Integer>) data.get(CERTIFICATEPROFILEID)).get(certusage)).intValue();}


    /**
     * Field indicating if a certificate should be set to rewritable on the token.
     * 
     * 
     * @param certusage should be one of the CERTUSAGE_ constants.
     * @return boolean indicating if the certificate should be rewritabes, if false 
     * the certificate is written as read-only and cannot be renewed.
     */
    @SuppressWarnings("unchecked")
    public boolean getCertWritable(int certusage){ return ((Boolean) ((List<Boolean>) data.get(CERTWRITABLE)).get(certusage)).booleanValue();}
    
	/**
	 * Indicates which ca id that should be requested when
	 * generating certificate of given certusage.
	 * 
	 * RESERVED FOR FUTURE USE
	 * 
	 * @param certusage should be one of the CERTUSAGE_ constants.
	 * @return The caid that should be used.
	 */
	@SuppressWarnings("unchecked")
    public int getCAId (int certusage){return ((Integer) ((List<Integer>) data.get(CAID)).get(certusage)).intValue();}


	/**
	 * Indicates if a keys used for the given certusage should be saved to database.
	 * 
	 * @param certusage should be one of the CERTUSAGE_ constants.
	 * @return true if the keys used for the certusage should be saved to database.
	 */
	@SuppressWarnings("unchecked")
    public boolean getIsKeyRecoverable (int certusage){return ((Boolean) ((List<Boolean>) data.get(ISKEYRECOVERABLE)).get(certusage)).booleanValue();}

	/**
	 * Indicates if the certificate should be reused when recovering a token. This
	 * since some application requires the same certificate when decrypting data.
	 * 
	 * @param certusage should be one of the CERTUSAGE_ constants.
	 * @return true if the certificate should bereused
	 */
	@SuppressWarnings("unchecked")
    public boolean getReuseOldCertificate (int certusage){return ((Boolean) ((List<Boolean>) data.get(REUSEOLDCERTIFICATE)).get(certusage)).booleanValue();}
	
	/**
	 * Gives the minimum key length allowed. 
	 * Generally will the tokens maximum kapacity of key be generated
	 * 
	 * @param certusage should be one of the CERTUSAGE_ constants.
	 * @return The caid that should be used.
	 */
	@SuppressWarnings("unchecked")
    public int getMinimumKeyLength (int certusage){return ((Integer) ((List<Integer>) data.get(MINIMUMKEYLENGTH)).get(certusage)).intValue(); }

	/**
	 * Indicates which type of key that should be generated for the certusage.
	 * 
	 * RESERVED FOR FUTURE USE
	 * 
	 * @param certusage should be one of the CERTUSAGE_ constants.
	 * @return The keytype that should be generated, one of the KEYTYPE_ Constants
	 */
	@SuppressWarnings("unchecked")
    public String getKeyType (int certusage){return ((String) ((List<String>) data.get(KEYTYPES)).get(certusage)); }

	// Public Methods used By EJBCA

	/**
	 * See above
	 */
	public void setCertificateProfileId(int certusage, int certprofileid){
		@SuppressWarnings("unchecked")
	  List<Integer> list = (List<Integer>) data.get(CERTIFICATEPROFILEID);	  
	  list.set(certusage, Integer.valueOf(certprofileid));
	  data.put(CERTIFICATEPROFILEID, list);
	}

	
	/**
	 * See above
	 */
    @SuppressWarnings("unchecked")
	public void setCertWritable(int certusage, boolean certWritable){ 
		List<Boolean> list = (List<Boolean>) data.get(CERTWRITABLE);	  
		list.set(certusage, Boolean.valueOf(certWritable));
		data.put(CERTWRITABLE, list);
    }
	
	/**
	 * See above
	 */
	@SuppressWarnings("unchecked")
	public void setCAId (int certusage, int caid){
      List<Integer> list = (List<Integer>) data.get(CAID);	  
	  list.set(certusage, Integer.valueOf(caid));
	  data.put(CAID, list);		
	}

	/**
	 * See above
	 */
	@SuppressWarnings("unchecked")
	public void setIsKeyRecoverable (int certusage, boolean iskeyrecoverable){		
		List<Boolean> list = (List<Boolean>) data.get(ISKEYRECOVERABLE);	  
		list.set(certusage, Boolean.valueOf(iskeyrecoverable));
		data.put(ISKEYRECOVERABLE, list);		
	}
	
	/**
	 * See above
	 */
	@SuppressWarnings("unchecked")
	public void setReuseOldCertificate (int certusage, boolean reuseoldcertificate){
		List<Boolean> list = (List<Boolean>) data.get(REUSEOLDCERTIFICATE);	  
		list.set(certusage, Boolean.valueOf(reuseoldcertificate));
		data.put(REUSEOLDCERTIFICATE, list);				
	}

	/**
	 * See above
	 */
	@SuppressWarnings("unchecked")
	public void setMinimumKeyLength (int certusage, int minimumkeylength){		
		List<Integer> list = (List<Integer>) data.get(MINIMUMKEYLENGTH);	  
		list.set(certusage, Integer.valueOf(minimumkeylength));
		data.put(MINIMUMKEYLENGTH, list);				 
	}

	/**
	 * See above
	 */
	@SuppressWarnings("unchecked")
	public void setKeyType (int certusage, String keytype){
	  List<String> list = (List<String>) data.get(KEYTYPES);	  
	  list.set(certusage, keytype);
	  data.put(KEYTYPES, list);				 
	}
	
	/**
	 * Returns a collection of all defined certificate profiles.
	 *
	 */
	@SuppressWarnings("unchecked")
    public Collection<Integer> getAllCertificateProfileIds(){
	  return (Collection<Integer>) data.get(CERTIFICATEPROFILEID);	
	}
	
	/**
	 * Returns all valid CAids, if a certusage have CAID_USEUSERDEFINED defined then
	 * it will not be among available valus in returned collection.
	 * 
	 * @return
	 */
	public Collection<Integer> getAllCAIds(){
		@SuppressWarnings("unchecked")
      Collection<Integer> caids = (Collection<Integer>) data.get(CAID);	
      List<Integer> retval = new ArrayList<Integer>();
      Iterator<Integer> iter = caids.iterator();
      while(iter.hasNext()){
      	Integer value = (Integer) iter.next();
      	if(value.intValue() > CAInfo.SPECIALCAIDBORDER || value.intValue() < 0){
      	  retval.add(value);
      	}      	
      }
      
      return retval;
	}	
	
	public abstract int[] getAvailableMinimumKeyLengths();
	  		      
    // Protected methods
	public boolean isTokenSupported(String[][] supportedcards, String tokenidentificationstring){
      boolean returnval = true;	
      @SuppressWarnings("unchecked")
      Iterator<Integer> iter = ((List<Integer>) data.get(MINIMUMKEYLENGTH)).iterator();
	  int[] availablekeylengths = getAvailableMinimumKeyLengths();
	  
      while(iter.hasNext()){
      	int index = -1;
      	int keylength = iter.next().intValue();
        for(int i=0;i<availablekeylengths.length;i++){
		  if(availablekeylengths[i] == keylength){
		  	index=i;
		  	break;   		 	
		  }
        }        
        returnval = returnval && super.isTokenSupported(supportedcards[index], tokenidentificationstring);        
      }
    	    	
      return returnval;	 
    }
    
    /**
     * Help Method that should be used 
     * @param emptyclone
     */
    
    @SuppressWarnings("rawtypes")
    public void clone(EIDProfile emptyclone){
		java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();

		try{
			ObjectOutputStream oos = new ObjectOutputStream(baos);	
			oos.writeObject(this.saveData());
			oos.close();
			ObjectInputStream ois = new ObjectInputStream(new java.io.ByteArrayInputStream(baos.toByteArray()));
            HashMap cloneddata = (HashMap) ois.readObject();		
			ois.close();
			emptyclone.loadData(cloneddata);
		}catch(Exception e){
			throw new RuntimeException(e);
		}   	    
    }

    /**
     * Method used to reinit a hardtoken profile to its default values.
     * Used when changing the profile but want to keep the values that
     * are in common between the two types.
     */
    public abstract void reInit();

}
