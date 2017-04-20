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
package org.ejbca.core.ejb.upgrade;

public interface UpgradeSession {

    /**
     * Upgrades the database
     * 
     * @return true or false if upgrade was done or not
     */
    public boolean upgrade(String dbtype, String sOldVersion, boolean isPost);
    
    /**Access rules removed from EJBCA 6.8.0*/
    String ROLE_PUBLICWEBUSER               = "/public_web_user";
    String REGULAR_CABASICFUNCTIONS_OLD     = "/ca_functionality/basic_functions";
    String REGULAR_ACTIVATECA_OLD           = REGULAR_CABASICFUNCTIONS_OLD+"/activate_ca";
}
