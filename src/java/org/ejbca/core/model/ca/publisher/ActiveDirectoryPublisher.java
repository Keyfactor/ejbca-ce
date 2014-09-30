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
 
package org.ejbca.core.model.ca.publisher;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.certificates.util.DNFieldExtractor;
import org.cesecore.util.CertTools;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPModification;

/**
 * ActiveDirectoryPublisher is a class handling a publishing to Active Directory catalouges.  
 *
 * @version $Id$
 */
public class ActiveDirectoryPublisher extends LdapPublisher{
	
	private static final long serialVersionUID = 1081937637762724531L;

    private static final Logger log = Logger.getLogger(ActiveDirectoryPublisher.class);
	 	
	public static final float LATEST_VERSION = 1;
	
	// Constants indicating characteristics of created user accounts
	public static final int UAC_DISABLE           = 2;
	public static final int UAC_NORMAL            = 512;
	public static final int UAC_NEVEREXPIRE       = 66048;
	public static final int UAC_SMARTCARDREQUIRED = 0x40000;
	
	// Default Values	
	public static final int DEFAULT_UAC         = UAC_NEVEREXPIRE;
    
    protected static final String USEPASSWORD                = "usepassword";
    protected static final String USERACCOUNTCONTROL         = "useraccountcontrol";
    protected static final String SAMACCOUNTNAME             = "samaccountname";
    protected static final String USERDESCRIPTION            = "userdescription";

	public static final String DEFAULT_USEROBJECTCLASS       = "top;person;organizationalPerson;user";
	public static final String DEFAULT_CAOBJECTCLASS         = "top;cRLDistributionPoint";
    

    
    public ActiveDirectoryPublisher(){
    	super();
    	data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_ADPUBLISHER));
    	    	
        setUserObjectClass(DEFAULT_USEROBJECTCLASS);
        setCAObjectClass(DEFAULT_CAOBJECTCLASS);
        setUseUserPassword(true);
        setUserAccountControl(DEFAULT_UAC);
        setSAMAccountName(DNFieldExtractor.UPN);
        setUserDescription("");
    }
    
    
    
    /**
     *  Returns true if user password should be set when creating users.
     */    
    public boolean getUseUserPassword (){
    	return ((Boolean) data.get(USEPASSWORD)).booleanValue();
    }

    /**
     *  Sets if user password should be set when creating users.
     */        
    public void setUseUserPassword (boolean useuserpassword){
    	data.put(USEPASSWORD, Boolean.valueOf(useuserpassword));	
    }

    /**
     *  Returns the value of the user account control
     */    
    public int getUserAccountControl (){
    	return ((Integer) data.get(USERACCOUNTCONTROL)).intValue();
    }

    /**
     *  Sets the value of the user account control, (mask)
     */        
    public void setUserAccountControl(int useraccountcontrol){
    	data.put(USERACCOUNTCONTROL, Integer.valueOf(useraccountcontrol));	
    }

    /**
     *  Returns a DNFieldExtractor constant indicating which DN field to
     *  use as SAM Account Name.
     */    
    public int getSAMAccountName (){
    	return ((Integer) data.get(SAMACCOUNTNAME)).intValue();
    }

    /**
     *  Sets the SAM account name.
     * 
     *  @param samaccountname is one a DNFieldExtractor constant indicating
     *  which field to use as SAM Account Name.
     */        
    public void setSAMAccountName(int samaccountname){
    	data.put(SAMACCOUNTNAME, Integer.valueOf(samaccountname));	
    }

    /**
     *  Returns the description used for created users
     */    
    public String getUserDescription (){
    	return (String) data.get(USERDESCRIPTION);
    }

    /**
     *  Sets the value of the user account control, (mask)
     */        
    public void setUserDescription(String userdescription){
    	data.put(USERDESCRIPTION, userdescription);	
    }
    
    /** Overrides LdapPublisher.getAttributeSet
     * Creates an LDAPAttributeSet.
     * 
     * @param cert is the certificate about to be published
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the attributeset.
     * @param pserson true if this is a person-entry, false if it is a CA.
     * @param password to set for the user, if null no password is set.
     * @param extendedinformation, for future use...
     *
     * @return LDAPAtributeSet created...
     */
    protected LDAPAttributeSet getAttributeSet(Certificate cert, String objectclass, String dn, String email, boolean extra, boolean person, 
    		                                   String password, ExtendedInformation extendedinformation) {
    	log.debug("ADPublisher : getAttributeSet");
    	
        LDAPAttributeSet attributeSet = super.getAttributeSet(cert, objectclass, dn, email, extra, person, password, extendedinformation);
        
        String cn = CertTools.getPartFromDN(dn, "CN");
        // Add AD specific attributes
        //attributeSet.add(new LDAPAttribute("userAccountControl", Integer.toString(getUserAccountControl())));
        
        if(cert!= null && cert instanceof X509Certificate){
          String upn = null;
		try {
			upn = CertTools.getUPNAltName((X509Certificate) cert);
		} catch (CertificateParsingException e) {}
		  catch (IOException e) {}
		String samaccountname = upn;
		if(upn != null && upn.indexOf('@') != -1){
		  // only use name part of UPN.
			samaccountname = samaccountname.substring(0, upn.indexOf('@'));	
		}
		
		
          switch(getSAMAccountName()){
        	case DNFieldExtractor.CN:
              samaccountname = cn;   
              break;
            case DNFieldExtractor.UID:  
              samaccountname = CertTools.getPartFromDN(dn, "UID");   
              break;        	
          }
          if(samaccountname !=null){
            attributeSet.add(new LDAPAttribute("samaccountname", samaccountname));
          }
          
          if(upn != null) {
          	attributeSet.add(new LDAPAttribute("userPrincipalName", upn));    
          } else {
          	attributeSet.add(new LDAPAttribute("userPrincipalName", cn));
          }
        }
        attributeSet.add(new LDAPAttribute("displayName", cn));
        if(getUserDescription() != null && !getUserDescription().trim().equals("")){
          attributeSet.add(new LDAPAttribute("description", getUserDescription()));
        }

        if(getConnectionSecurity() == ConnectionSecurity.SSL  && password != null){
          //Can only set password through SSL connection
        	
        	//attributeSet.add(new LDAPAttribute("userPassword", password));	
          

          //Start out by taking the password and enclosing it in quotes, as in
            String newVal = new String("\"" + password + "\"");

          //Then, you need to get the octet string of the Unicode representation of
          //that.  You need to leave off the extra two bytes Java uses as length:
            
            byte _bytes[] = null;
			try {
				_bytes = newVal.getBytes("Unicode");
			} catch (UnsupportedEncodingException e) {}
			byte bytes[] = new byte[_bytes.length - 2];
            System.arraycopy(_bytes, 2, bytes, 0, _bytes.length - 2);

          //Take that value and stuff it into the unicodePwd attribute:          
            attributeSet.add(new LDAPAttribute("unicodePwd", bytes));                   
          
        }  
        
        
        return attributeSet;
    } // getAttributeSet
	
	
    /** Overrides LdapPublisher.getModificationSet
     */
    @Override
    protected ArrayList<LDAPModification> getModificationSet(LDAPEntry oldEntry, String dn, String email, boolean extra, boolean person, String password, Certificate cert) {
    	ArrayList<LDAPModification> modSet = super.getModificationSet(oldEntry, dn, email, false, person, null, cert);

		// Modify AD specific attributes
		
        return modSet;
    } // getModificationSet

         
    
    
    // Private methods
		
	/** 
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
		ActiveDirectoryPublisher clone = new ActiveDirectoryPublisher();
		@SuppressWarnings("unchecked")
        HashMap<Object, Object> clonedata = (HashMap<Object, Object>) clone.saveData();

		Iterator<Object> i = (data.keySet()).iterator();
		while(i.hasNext()){
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}

		clone.loadData(clonedata);
		return clone;	
		}

	/* *
	 * @see org.ejbca.core.model.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}
	

}
