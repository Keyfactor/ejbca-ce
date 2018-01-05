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

package org.ejbca.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

/**
 * 
 * @version $Id$
 *
 */
public class ConfigurationHolder {

    private Properties properties;
    private ClassLoader configCl = ConfigurationHolder.class.getClassLoader();
    
    public ConfigurationHolder() {
        this.properties = new Properties();
    }

    public void loadAllProperties() {
        try {
            properties.load(new FileInputStream(configCl.getResource("appserver.properties").getFile()));
            properties.load(new FileInputStream(configCl.getResource("ejbca.properties").getFile()));
            properties.load(new FileInputStream(configCl.getResource("profiles.properties").getFile()));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void setGeckoDriver() {
        System.setProperty("webdriver.gecko.driver", configCl.getResource("geckodriver").getFile());
    }
    
    public String getProperty(String property) {
        return properties.getProperty(property);
    }
}
