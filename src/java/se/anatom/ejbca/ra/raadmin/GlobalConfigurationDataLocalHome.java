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
 
package se.anatom.ejbca.ra.raadmin;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;

/**
For docs, see GlobalWebConfigurationBean
*/
public interface GlobalConfigurationDataLocalHome extends javax.ejb.EJBLocalHome {

    public GlobalConfigurationDataLocal create(String id, GlobalConfiguration globalconfiguration)
        throws CreateException;
    public GlobalConfigurationDataLocal findByPrimaryKey(String id)
        throws FinderException;
    public GlobalConfigurationDataLocal findByConfigurationId(String id)
        throws FinderException;
}
