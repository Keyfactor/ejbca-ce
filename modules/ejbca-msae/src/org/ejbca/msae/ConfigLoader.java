/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import org.apache.log4j.Logger;

import javax.servlet.ServletContext;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * 
 * @version $Id$
 */
public class ConfigLoader extends Properties {

    private static final Logger log = Logger.getLogger(ConfigLoader.class);

	private static final long serialVersionUID = -5828702341740710152L;

    public ConfigLoader(ServletContext context) {
        this.context = context;
    }

    private ServletContext context;
    private static String pathToConfigDirectory;

    public static String getPathToConfigDirectory() {
        return pathToConfigDirectory;
    }

    private InputStream getPropertiesStream(ServletContext context) {
        String autoenrollConfigFile = "autoenroll_config_directory.properties";
        return context.getResourceAsStream("/WEB-INF/" + autoenrollConfigFile);
    }

    boolean loadContext() {
        boolean rc = false;
        try {
            InputStream in = getPropertiesStream(context);
            super.load(in);
            in.close();

            pathToConfigDirectory = getProperty("Config_Directory", "/WEB-INF/");

            rc = true;
        }
        catch (FileNotFoundException ex) {
            log.error("FileNotFoundException: ", ex);
        }
        catch (IOException e) {
            log.error("IOException: ", e);
        }

        return rc;
    }

}
