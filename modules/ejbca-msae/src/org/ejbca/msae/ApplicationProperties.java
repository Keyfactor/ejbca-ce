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

public class ApplicationProperties {

    private static final Logger log = Logger.getLogger(ApplicationProperties.class);

    private static final String MSENROLLMENTSERVLETPROPERTIES = "MSEnrollmentServlet.properties";

    private String URLWEBSERVICE;
    // TODO These are stored as plain text.  They should be encrypted or obfuscated in some fashion.
    private String KEYSTORE;
    private String KEYSTOREPASSWORD;
    private String TRUSTEDKEYSTORE;
    private String TRUSTEDKEYSTOREPASSWORD;
    private String CANAME;
    private String BASEURL = "https://www.digicert.com/services/v2";
    private String APIKEY = "";
    private String CA = "ejbca";

    private Properties msEnrollment = new Properties();

    ApplicationProperties(String configPath) {
        this.loadConfig(configPath);
    }

    private void loadConfig(String configPath) {

		/* Load MSEnrollmentServlet.properties */
        try {
            InputStream in = new FileInputStream(configPath + MSENROLLMENTSERVLETPROPERTIES);
            msEnrollment.load(in);
            in.close();
            URLWEBSERVICE = msEnrollment.getProperty("EJBCA_WebServiceUrl", "");
            KEYSTORE = msEnrollment.getProperty("EJBCA_KeyStore", "");
            KEYSTOREPASSWORD = msEnrollment.getProperty("EJBCA_KeyStorePassword", "");
            TRUSTEDKEYSTORE = msEnrollment.getProperty("EJBCA_TrustedKeyStore", "");
            TRUSTEDKEYSTOREPASSWORD = msEnrollment.getProperty("EJBCA_TrustedKeyStorePassword", "");
            CANAME = msEnrollment.getProperty("EJBCA_CAName", "");
            BASEURL = msEnrollment.getProperty("BASE_URL", "https://www.digicert.com/services/v2");
            APIKEY = msEnrollment.getProperty("APIKey", "");
            CA = msEnrollment.getProperty("CA", "ejbca");
        } catch (FileNotFoundException ex) {
            log.error("FileNotFoundException: ", ex);
        } catch (IOException e) {
            log.error("IOException: ", e);
        }
    }

	public String getURLWEBSERVICE() {
		return URLWEBSERVICE;
	}

	public String getKEYSTORE() {
		return KEYSTORE;
	}

	public String getKEYSTOREPASSWORD() {
		return KEYSTOREPASSWORD;
	}

	public String getTRUSTEDKEYSTORE() {
		return TRUSTEDKEYSTORE;
	}

	public String getTRUSTEDKEYSTOREPASSWORD() {
		return TRUSTEDKEYSTOREPASSWORD;
	}

	public String getCANAME() {
		return CANAME;
	}

	public String getBASEURL() {
		return BASEURL;
	}

	public String getAPIKEY() {
		return APIKEY;
	}

	public String getCA() {
		return CA;
	}
}