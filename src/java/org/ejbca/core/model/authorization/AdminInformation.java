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
 
/*
 * AdminInformation.java
 *
 * Created on den 19 juli 2002, 11:53
 */

package org.ejbca.core.model.authorization;

import java.security.cert.Certificate;

/**
 * A class used to send user information to the authorization tree. It can contain types of information, a X509Certificate or a
 * special user type when certificates cannot be retrieved. Special usertype constants is specified in AdminEntity class.
 *
 * @version $Id$
 */
public class AdminInformation implements java.io.Serializable {

    // Public Methods
    /** Creates a new instance of AdminInformation */
    public AdminInformation(Certificate certificate){
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

    public Certificate getX509Certificate() {
      return this.certificate;
    }

    public int getSpecialUser() {
      return this.specialuser;
    }
    
    public int getGroupId(){
      return this.admingroup.getAdminGroupId();	
    }

    // Private fields
    private Certificate certificate;
    private int specialuser = 0;
    private AdminGroup admingroup = null;
}
