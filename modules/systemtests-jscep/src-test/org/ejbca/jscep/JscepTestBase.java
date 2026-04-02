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
package org.ejbca.jscep;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

import org.cesecore.SystemTestsConfiguration;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;

/**
 * Base class for jscep test classes
 */
public abstract class JscepTestBase {

    private ConfigurationSessionRemote configurationSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(ConfigurationSessionRemote.class,
            EjbRemoteHelper.MODULE_TEST);
    
    protected URL getUrl(final String alias) throws MalformedURLException, URISyntaxException {
        String httpHost = SystemTestsConfiguration.getRemoteHost("127.0.0.1");
        String httpPort = SystemTestsConfiguration
                .getRemotePortHttp(configurationSessionRemote.getProperty(WebConfiguration.CONFIG_HTTPSERVERPUBHTTP));
        String resourceName = "/ejbca/publicweb/apply/scep/" + alias + "/pkiclient.exe";
        
        return new URI( "http://" + httpHost + ":" + httpPort + resourceName).toURL();
    }
}
