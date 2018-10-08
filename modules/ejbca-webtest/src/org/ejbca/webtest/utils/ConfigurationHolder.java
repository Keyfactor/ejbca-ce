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
package org.ejbca.webtest.utils;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URL;
import java.util.Properties;

/**
 * This class holds the user configuration for the EJBCA Webtest module.
 * The configuration is loaded from property files located in modules/ejbca-webtest/conf.
 * @version $Id: ConfigurationHolder.java 28846 2018-05-04 11:32:25Z oskareriksson $
 */
public class ConfigurationHolder {
    private ClassLoader configCl = ConfigurationHolder.class.getClassLoader();
    private Properties properties;

    public ConfigurationHolder() {
        this.properties = new Properties();
    }

    public void loadAllProperties() {
        try {
            loadProperty("appserver");
            loadProperty("ejbca");
            loadProperty("profiles");
            loadProperty("browser");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadProperty(final String property) throws IOException {
        final URL userProperty = configCl.getResource(property + ".properties");
        if (userProperty != null) {
            properties.load(new FileInputStream(userProperty.getFile()));
            return;
        }
        final URL defaultProperty = configCl.getResource(property + ".properties.sample");
        if (defaultProperty != null) {
            properties.load(new FileInputStream(defaultProperty.getFile()));
            return;
        }
        throw new FileNotFoundException("Property file for " + property + " could not be found.");
    }

    public void setGeckoDriver() {
        System.setProperty("webdriver.gecko.driver", configCl.getResource("geckodriver").getFile());
    }

    public String getProperty(String property) {
        return properties.getProperty(property);
    }
}
