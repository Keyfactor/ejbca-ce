package se.anatom.ejbca.ca.publisher;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.util.CertTools;

import com.novell.ldap.LDAPAttribute;
import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPModificationSet;

/**
 * ActiveDirectoryPublisher is a class handling a publishing to Active Directory catalouges.  
 *
 * @version $Id: ActiveDirectoryPublisher.java,v 1.2 2004-03-14 13:49:21 herrvendil Exp $
 */
public class ActiveDirectoryPublisher extends LdapPublisher{
	
	private static Logger log = Logger.getLogger(ActiveDirectoryPublisher.class);
	 	
	public static final float LATEST_VERSION = 1;

	public static final int TYPE_ADPUBLISHER = 3;
	
	// Constants indicating characteristics of created user accounts
	public static final int UAC_DISABLE = 2;
	public static final int UAC_NORMAL = 512;
	public static final int UAC_NEVEREXPIRE = 66048;

	// Default Values	
	public static final int DEFAULT_UAC         = UAC_NEVEREXPIRE;
    
    protected static final String USEPASSWORD                = "usepassword";
    protected static final String USERACCOUNTCONTROL         = "useraccountcontrol";
    protected static final String SAMACCOUNTNAME             = "samaccountname";
    protected static final String USERDESCRIPTION            = "userdescription";

	public static final String DEFAULT_USEROBJECTCLASS       = "top;person;organizationalPerson;user";
	public static final String DEFAULT_CAOBJECTCLASS         = "top;certificationAuthority";
    

    
    public ActiveDirectoryPublisher(){
    	super();
    	data.put(TYPE, new Integer(TYPE_ADPUBLISHER));
    	    	
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
    	data.put(USEPASSWORD, new Boolean(useuserpassword));	
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
    	data.put(USERACCOUNTCONTROL, new Integer(useraccountcontrol));	
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
    	data.put(SAMACCOUNTNAME, new Integer(samaccountname));	
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
    
    /**
     * Creates an LDAPAttributeSet.
     *
     * @param objectclass the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the attributeset.
     * @param pserson true if this is a person-entry, false if it is a CA.
     *
     * @return LDAPAtributeSet created...
     */
    protected LDAPAttributeSet getAttributeSet(X509Certificate cert, String objectclass, String dn, boolean extra, boolean person) {
    	System.out.println("ADPublisher : getAttributeSet");
        LDAPAttributeSet attributeSet = super.getAttributeSet(cert, objectclass, dn, extra, person);
        String cn = CertTools.getPartFromDN(dn, "CN");
        // Add AD specific attributes
        attributeSet.add(new LDAPAttribute("userAccountControl", Integer.toString(getUserAccountControl())));
        
        if(cert!= null){
          String upn = null;
		try {
			upn = CertTools.getUPNAltName(cert);
		} catch (CertificateParsingException e) {}
		  catch (IOException e) {}
		String samaccountname = upn;
		if(upn != null && upn.indexOf('@') != -1){
		  // only use name part of UPN.
			samaccountname = samaccountname.substring(upn.indexOf('@'));	
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
          
          if(upn != null)
          	attributeSet.add(new LDAPAttribute("userPrincipalName", upn));    
          else
          	attributeSet.add(new LDAPAttribute("userPrincipalName", cn));
        }
        attributeSet.add(new LDAPAttribute("displayName", cn));
        attributeSet.add(new LDAPAttribute("description", getUserDescription()));
        

        if(getUseSSL() && getUseUserPassword()){
        	// TODO fix better
        	String password = "foo123"; 
          //Can only set password through SSL connection
        	attributeSet.add(new LDAPAttribute("userPassword", password));	
          

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
	
	
    /**
     * Creates an LDAPModificationSet.
     *
     * @param oldEntry the objectclass the attribute set should be of.
     * @param dn dn of the LDAP entry.
     * @param extra if we should add extra attributes except the objectclass to the
     *        modificationset.
     * @param pserson true if this is a person-entry, false if it is a CA.
     *
     * @return LDAPModificationSet created...
     */
    protected LDAPModificationSet getModificationSet(LDAPEntry oldEntry, String dn, boolean extra, boolean person) {
        LDAPModificationSet modSet = super.getModificationSet(oldEntry, dn, extra, person);

		// Modify AD specific attributes
		
        return modSet;
    } // getModificationSet

        
    
    
    // Private methods
		
	/** 
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher#clone()
	 */
	public Object clone() throws CloneNotSupportedException {
		ActiveDirectoryPublisher clone = new ActiveDirectoryPublisher();
		HashMap clonedata = (HashMap) clone.saveData();

		Iterator i = (data.keySet()).iterator();
		while(i.hasNext()){
			Object key = i.next();
			clonedata.put(key, data.get(key));
		}

		clone.loadData(clonedata);
		return clone;	
		}

	/* *
	 * @see se.anatom.ejbca.ca.publisher.BasePublisher#getLatestVersion()
	 */
	public float getLatestVersion() {		
		return LATEST_VERSION;
	}
	

}
