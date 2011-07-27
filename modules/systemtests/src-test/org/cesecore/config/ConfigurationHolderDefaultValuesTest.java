/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.config;

import org.cesecore.configuration.ConfigurationHolderProxySessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.junit.Assert;
import org.junit.Test;

/**
 * Functional tests to check that the ConfigurationHolder can find its values when deployed in the AS.  
 * 
 * Based on cesecore version:
 *      ConfigurationHolderDefaultValuesTest.java 948 2011-07-18 09:04:26Z mikek
 * 
 * @version $Id$
 * 
 */
public class ConfigurationHolderDefaultValuesTest {
    
    ConfigurationHolderProxySessionRemote configurationHolderProxySession = JndiHelper.getRemoteSession(ConfigurationHolderProxySessionRemote.class);
    
    @Test
    public void testDefaultValues() {
        Assert.assertEquals("cesecore", configurationHolderProxySession.getDefaultValue("database.name"));
    }

}
