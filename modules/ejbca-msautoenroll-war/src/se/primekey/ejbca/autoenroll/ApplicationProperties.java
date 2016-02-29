/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package se.primekey.ejbca.autoenroll;

/**
 * @author Daniel Horn, SiO2 Corp.
 * 
 * @version $Id$
*/
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import javax.servlet.ServletContext;

public class ApplicationProperties extends Properties
{

    private String urlWebService = ""; 	// eg, "https://ejbca.course:8443/ejbca/ejbcaws/ejbcaws?wsdl"
    // TODO These are stored as plain text.  They should be encrypted or obfuscated in some fashion.
    private String strKeyStore = ""; 	// "/Users/danielhorn/Downloads/test1.jks";
    private String strKeyStorePassword = "";	// "foo123"
    private String strTrustedKeyStore = ""; 	// "/Users/danielhorn/Downloads/test1.jks";
    private String strTrustedKeyStorePassword = "";	// "foo123"
    private String strCAName = "";
        
    /**
     * 
     */
//    public ApplicationProperties()
//    {
//    }

    /**
     * @param defaults
     */
//    public ApplicationProperties(Properties defaults)
//    {
//        super(defaults);
//    }

    public ApplicationProperties(ServletContext context)
    {
        load(context);
    }
    
    
    // TODO What should the name be?
    private static final String strFileName = "MSEnrollmentServlet.properties";

    private InputStream getPropertiesStream(ServletContext context)
    {
        /** TODO: Properties file is located in /Applications/apache-tomcat-6.0.32/bin/ directory.
         * Move it someplace more reasonable.
         */
        return context.getResourceAsStream("/WEB-INF/" + strFileName);
    }

    boolean load(ServletContext context)
    {
        boolean rc = false;
        try
        {
            InputStream in = getPropertiesStream(context);
            super.load(in);
            in.close();

            setUrlWebService(getProperty("EJBCA_WebServiceUrl", ""));
            setKeyStoreStr(getProperty("EJBCA_KeyStore", ""));
            strKeyStorePassword = getProperty("EJBCA_KeyStorePassword", "");
            strTrustedKeyStore = getProperty("EJBCA_TrustedKeyStore", "");
            strTrustedKeyStorePassword = getProperty("EJBCA_TrustedKeyStorePassword", "");
            strCAName = getProperty("EJBCA_CAName", "");

            rc = true;
        }
        catch (FileNotFoundException ex)
        {
            // Probably should be created first time app is run, so exception here is not a problem as long as reasonable defaults are set.
            ex.printStackTrace();
        }
        catch (IOException e)
        {
            e.printStackTrace();
        }

        return rc;
    }

    // The validity check here is just to see if the settings are non-empty.
    boolean isValid()
    {
        if ((0 == urlWebService.length())
                || (0 == strKeyStore.length())
                || (0 == strKeyStorePassword.length())
                || (0 == strTrustedKeyStore.length())
                || (0 == strTrustedKeyStorePassword.length()))
        {
            return false;
        }

        return true;
    }

    public String getKeyStoreStr()
    {
        return strKeyStore;
    }

    public void setKeyStoreStr(String strKeyStore)
    {
        this.strKeyStore = strKeyStore;
        setProperty("EJBCA_KeyStore", strKeyStore);
    }
//
    public String getKeyStorePassword()
    {
        return strKeyStorePassword;
    }

    public void setKeyStorePassword(String strKeyStorePassword)
    {
        this.strKeyStorePassword = strKeyStorePassword;
        setProperty("EJBCA_KeyStorePassword", strKeyStorePassword);
    }

    public String getTrustedKeyStoreStr()
    {
        return strTrustedKeyStore;
    }

    public void setTrustedKeyStoreStr(String strTrustedKeyStore)
    {
        this.strTrustedKeyStore = strTrustedKeyStore;
        setProperty("EJBCA_TrustedKeyStore", strTrustedKeyStore);
    }

    public String getTrustedKeyStorePassword()
    {
        return strTrustedKeyStorePassword;
    }

    public void setTrustedKeyStorePassword(String strTrustedKeyStorePassword)
    {
        this.strTrustedKeyStorePassword = strTrustedKeyStorePassword;
        setProperty("EJBCA_TrustedKeyStorePassword", strTrustedKeyStorePassword);
    }

    public String getUrlWebService()
    {
        return urlWebService;
    }

    public void setUrlWebService(String urlWebService)
    {
        this.urlWebService = urlWebService;
        setProperty("EJBCA_WebServiceUrl", urlWebService);
    }

    public String getCAName()
    {
        return strCAName;
    }

    // For debugging:
    @Override
    public String toString()
    {
        String result = "UrlWebService: " + getProperty("EJBCA_WebServiceUrl", "")
                + "\nKeyStore: " + getProperty("EJBCA_KeyStore", "")
                + "\nKeyStorePassword: " + getProperty("EJBCA_KeyStorePassword", "")
                + "\nTrustedKeyStore: " + getProperty("EJBCA_TrustedKeyStore", "")
                + "\nTrustedKeyStorePassword: " + getProperty("EJBCA_TrustedKeyStorePassword", "")
                + "\nCAName: " + getProperty("EJBCA_CAName", "")
                ;

        return result;
    }
}
