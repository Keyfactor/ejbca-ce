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


import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;

/**
For docs, see GlobalWebConfigurationDataBean
*/
public interface GlobalConfigurationDataLocal extends javax.ejb.EJBLocalObject {
    // public methods
    public String getConfigurationId();
    public void setConfigurationId(String id);
    public GlobalConfiguration getGlobalConfiguration();
    public void setGlobalConfiguration(GlobalConfiguration globalConfiguration);
}

