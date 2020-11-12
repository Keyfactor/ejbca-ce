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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class PublisherProperties {

    private static final Logger log = Logger.getLogger(PublisherProperties.class);
    private static final String MSAESPROPERTIES = "msaes.properties";

    private String USESSL;
    private String PORT;
    private String LOGINDN;
    private String LOGINPASSWORD;

    private Properties msaes = new Properties();

    PublisherProperties(String configDirectory) {
        this.loadConfig(configDirectory);
    }

    private void loadConfig(String configDirectory) {
        /* Load msaes.properties */
        try {
            InputStream in = new FileInputStream(configDirectory + MSAESPROPERTIES);
            msaes.load(in);
            in.close();
            USESSL = msaes.getProperty("usessl", "");
            PORT = msaes.getProperty("port", "");
            LOGINDN = msaes.getProperty("logindn", "");
            LOGINPASSWORD = msaes.getProperty("loginpassword", "");
        } catch (FileNotFoundException ex) {
            log.error("FileNotFoundException: ", ex);
        } catch (IOException e) {
            log.error("IOException: ", e);
        }
    }

	public String getUSESSL() {
		return USESSL;
	}

	public String getPORT() {
		return PORT;
	}

	public String getLOGINDN() {
		return LOGINDN;
	}

	public String getLOGINPASSWORD() {
		return LOGINPASSWORD;
	}
}