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
 
package se.anatom.ejbca.hardtoken;

import se.anatom.ejbca.hardtoken.hardtokenprofiles.HardTokenProfile;



/**
 * For docs, see HardTokenProfileDataBean
 *
 * @version $Id: HardTokenProfileDataLocal.java,v 1.2 2004-04-16 07:38:56 anatom Exp $
 **/

public interface HardTokenProfileDataLocal extends javax.ejb.EJBLocalObject {

    // Public methods

    public Integer getId();

    public int getUpdateCounter();

    public void setName(String name);
    
	public String getName();
     
    public HardTokenProfile getHardTokenProfile();

    public void setHardTokenProfile(HardTokenProfile profile);
}

