/*
 * AdminInformation.java
 *
 * Created on den 19 juli 2002, 11:53
 */

package se.anatom.ejbca.authorization;

import java.security.cert.X509Certificate;

/**
 * A class used to send user information to the authorization tree. It can contain types of information, a X509Certificate or a
 * special user type when certificates cannot be retrieved. Special usertype constants is specified in AdminEntity class.
 *
 * @version $Id: AdminInformation.java,v 1.2 2004-01-08 14:31:26 herrvendil Exp $
 */
public class AdminInformation implements java.io.Serializable {

    // Public Methods
    /** Creates a new instance of AdminInformation */
    public AdminInformation(X509Certificate certificate){
      this.certificate=certificate;
      this.specialuser=0;      
    }
    
    public AdminInformation(int specialuser) {
      this.specialuser=specialuser;
	  
    }
    
	public AdminInformation(AdminGroup admingroup) {
	  this.specialuser=0;      
	  this.admingroup= admingroup;	  
	}


    public boolean isSpecialUser() {
      return this.specialuser!=0;
    }
    
    public boolean isGroupUser() {
      return this.admingroup != null;	
    }

    public X509Certificate getX509Certificate() {
      return this.certificate;
    }

    public int getSpecialUser() {
      return this.specialuser;
    }
    
    public int getGroupId(){
      return this.admingroup.getAdminGroupId();	
    }

    // Private fields
    private X509Certificate certificate;
    private int specialuser = 0;
    private AdminGroup admingroup = null;
}
