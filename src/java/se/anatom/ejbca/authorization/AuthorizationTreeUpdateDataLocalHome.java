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
 
package se.anatom.ejbca.authorization;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

/**
 * For docs, see AccessRulesDataBean
 **/
public interface AuthorizationTreeUpdateDataLocalHome extends javax.ejb.EJBLocalHome {

    public static final int AUTHORIZATIONTREEUPDATEDATA = 1;
    
    public AuthorizationTreeUpdateDataLocal create()
        throws CreateException;
    
    /**
     * Should only be called with the AUTHORIZATIONTREEUPDATEDATA constant.
     */
    public AuthorizationTreeUpdateDataLocal findByPrimaryKey(Integer pk)
        throws FinderException;
}
