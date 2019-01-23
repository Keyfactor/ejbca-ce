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

package org.ejbca.config;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.util.SlotList;

/**
 * This file handles configuration from web.properties
 */
public class WebConfiguration {

	private static final Logger log = Logger.getLogger(WebConfiguration.class);
	
	public static final String CONFIG_HTTPSSERVERHOSTNAME  = "httpsserver.hostname";
	public static final String CONFIG_HTTPSERVERPUBHTTP    = "httpserver.pubhttp";
    public static final String CONFIG_HTTPSERVERPUBHTTPS   = "httpserver.pubhttps";
	public static final String CONFIG_HTTPSSERVERPRIVHTTPS = "httpserver.privhttps";
	public static final String CONFIG_HTTPSSERVEREXTERNALPRIVHTTPS = "httpserver.external.privhttps";
    public static final String CONFIG_DOCBASEURI = "web.docbaseuri";
    public static final String CONFIG_REQCERT = "web.reqcert";
	public static final String CONFIG_REQCERTINDB = "web.reqcertindb";
	
	/**
	 * The configured server host name
	 */
	public static String getHostName() {
		return EjbcaConfigurationHolder.getExpandedString(CONFIG_HTTPSSERVERHOSTNAME);
	}
	
	/**
	 * Port used by EJBCA public webcomponents. i.e that doesn't require client authentication
	 */
	public static int getPublicHttpPort() {
		int value = 8080;
		try {
			value = Integer.parseInt(EjbcaConfigurationHolder.getString(CONFIG_HTTPSERVERPUBHTTP));
		} catch( NumberFormatException e ) {
			log.warn("\"httpserver.pubhttp\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}
	
	/**
	 * Port used by EJBCA private webcomponents. i.e that requires client authentication
	 */
	public static int getPrivateHttpsPort() {
		int value = 8443;
		try {
			value = Integer.parseInt(EjbcaConfigurationHolder.getString(CONFIG_HTTPSSERVERPRIVHTTPS));
		} catch( NumberFormatException e ) {
			log.warn("\"httpserver.privhttps\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}

	/**
	 * Port used by EJBCA public web to construct a correct url.
	 */
	public static int getExternalPrivateHttpsPort() {
		int value = getPrivateHttpsPort();
		try {
			value = Integer.parseInt(EjbcaConfigurationHolder.getString(CONFIG_HTTPSSERVEREXTERNALPRIVHTTPS));
		} catch( NumberFormatException e ) {
			log.warn("\"httpserver.external.privhttps\" is not a decimal number. Using default value: " + value);
		}
		return value;
	}

	/**
	 * Defines the available languages by language codes separated with a comma
	 */
	public static String getAvailableLanguages() {
		return EjbcaConfigurationHolder.getExpandedString("web.availablelanguages");
	}
	
	/**
	 * Setting to indicate if the secret information stored on hard tokens (i.e initial PIN/PUK codes) should
	 * be displayed for the administrators. If false only non-sensitive information is displayed. 
	 */
	public static boolean getHardTokenDiplaySensitiveInfo() {
		String value = EjbcaConfigurationHolder.getString("hardtoken.diplaysensitiveinfo");
		return "true".equalsIgnoreCase(value) || "yes".equalsIgnoreCase(value);
	}
	
	/**
	 * Show links to the EJBCA documentation.
	 * @return "disabled", "internal" or and URL
	 */
	public static String getDocBaseUri() {
		return EjbcaConfigurationHolder.getExpandedString(CONFIG_DOCBASEURI);
	}
	
	/**
	 * Require administrator certificates to be available to access the Admin GUI
	 */
	public static boolean getRequireAdminCertificate() {
        // Anything but an explicit setting this configuration value to "false" will enforce the client certificate check
	    return !Boolean.FALSE.toString().equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_REQCERT));
	}

    /**
     * Require administrator certificates to be available in database for revocation checks.
     */
    public static boolean getRequireAdminCertificateInDatabase() {
        return Boolean.valueOf(EjbcaConfigurationHolder.getExpandedString(CONFIG_REQCERTINDB));
    }

	/**
	 * Default content encoding used to display JSP pages
	 */
	public static String getWebContentEncoding() {
	   	return EjbcaConfigurationHolder.getString("web.contentencoding");
	}
	
	/**
	 * Whether self-registration (with admin approval) is enabled in public web
	 */
	public static boolean getSelfRegistrationEnabled() {
		return Boolean.valueOf(EjbcaConfigurationHolder.getExpandedString("web.selfreg.enabled"));
	}
	
	/**
	 * The request browser certificate renewal web application is deployed
	 */
	public static boolean getRenewalEnabled() {
		return Boolean.valueOf(EjbcaConfigurationHolder.getExpandedString("web.renewalenabled"));
	}

    public static boolean doShowStackTraceOnErrorPage(){
        final String s=EjbcaConfigurationHolder.getString ("web.errorpage.stacktrace");
        return s==null || s.toLowerCase().indexOf("true")>=0;
	}

    public static String notification(String sDefault){        
        String result= EjbcaConfigurationHolder.getString ("web.errorpage.notification");
        if(result == null) {
           return sDefault;            
        } else if(result.equals("")) {
           return sDefault;
        } else {
            return result;
        }
        
    }

    /** @return true if we allow proxied authentication to the Admin GUI. */
    public static boolean isProxiedAuthenticationEnabled(){
        return Boolean.valueOf(EjbcaConfigurationHolder.getString("web.enableproxiedauth"));
    }
    
        
    /**
     * Whether the remote IP address should be logged during administrator login.
     * This works as expected when using an Apache AJP proxy, but if a reverse proxy
     * server is running in front of EJBCA then the address of the proxy will be logged.
     */
    public static boolean getAdminLogRemoteAddress() {
        return !Boolean.FALSE.toString().equalsIgnoreCase(EjbcaConfigurationHolder.getString("web.log.adminremoteip"));
    }
    
    /**
     * Whether the IP address seen at the proxy (from the HTTP header "X-Forwarded-For")
     * should be logged. This information can only be trusted if the request
     * is known to come from a trusted proxy server.
     * 
     * @see getAdminLogRemoteAddress()
     */
    public static boolean getAdminLogForwardedFor() {
        return Boolean.valueOf(EjbcaConfigurationHolder.getString("web.log.adminforwardedip"));
    }
    
    /** @return true if the user is allowed to enter class names manually in the Publishers and Services pages */
    public static boolean isManualClassPathsEnabled() {
        return Boolean.valueOf(EjbcaConfigurationHolder.getString("web.manualclasspathsenabled"));
    }
    
    /** @return the script to use to create OpenVPN installers */
    public static String getOpenVPNCreateInstallerScript() {
        return EjbcaConfigurationHolder.getString("web.openvpn.createInstallerScript");
    }
    
    /** @return the default slot in the "New CryptoToken" page */
    public static String getDefaultP11SlotNumber() {
        String s = EjbcaConfigurationHolder.getString("cryptotoken.p11.defaultslot");
        return (s != null && !s.trim().isEmpty() ? s : "0");
    }
    
    public static final class P11LibraryInfo {
        private final String alias;
        private final SlotList slotList;
        private final boolean canGenerateKey;
        private final String canGenerateKeyMsg;
        public P11LibraryInfo(String alias, SlotList slotList, boolean canGenerateKey, String cangenerateKeyMsg) {
            this.alias = alias;
            this.slotList = slotList;
            this.canGenerateKey = canGenerateKey;
            this.canGenerateKeyMsg = cangenerateKeyMsg;
        }
        public String getAlias() { return alias; }
        public SlotList getSlotList() { return slotList; }
        public boolean isCanGenerateKey() { return canGenerateKey; }
        public String getCanGenerateKeyMsg() { return canGenerateKeyMsg;}
    }

    private static Map<String,P11LibraryInfo> availableP11LibraryToAliasMap = null;
    /** @return a (cached) mapping between the PKCS#11 libraries and their display names */
    public static Map<String,P11LibraryInfo> getAvailableP11LibraryToAliasMap() {
        if (availableP11LibraryToAliasMap==null) {
            final Map<String,P11LibraryInfo> ret = new HashMap<String,P11LibraryInfo>();
            for (int i=0; i<256; i++) {
                String fileName = EjbcaConfigurationHolder.getString("cryptotoken.p11.lib." + i + ".file");
                if (fileName!=null) {
                    String displayName = EjbcaConfigurationHolder.getString("cryptotoken.p11.lib." + i + ".name");
                    SlotList slotList = SlotList.fromString(EjbcaConfigurationHolder.getString("cryptotoken.p11.lib." + i + ".slotlist"));
                    final File file = new File(fileName);
                    if (file.exists()) {
                        fileName = file.getAbsolutePath();
                        if (displayName == null || displayName.length()==0) {
                            displayName = fileName;
                        }
                        boolean canGenerateKey = true;
                        String canGenerateKeyStr = EjbcaConfigurationHolder.getString("cryptotoken.p11.lib." + i + ".canGenerateKey");
                        if (StringUtils.equalsIgnoreCase("false", canGenerateKeyStr)) {
                            canGenerateKey = false; // make really sure it's true by default
                        }
                        String canGenerateKeyMsg = EjbcaConfigurationHolder.getString("cryptotoken.p11.lib." + i + ".canGenerateKeyMsg");
                        if (log.isDebugEnabled()) {
                            log.debug("Adding PKCS#11 library " + fileName + " with display name " + displayName+", canGenerateKey="+canGenerateKey+", canGenerateKeyMsg="+canGenerateKeyMsg);
                        }
                        ret.put(fileName, new P11LibraryInfo(displayName, slotList, canGenerateKey, canGenerateKeyMsg));
                    } else {
                        if (log.isDebugEnabled()) {
                            log.debug("PKCS#11 library " + fileName + " was not detected in file system and will not be available.");
                        }
                    }
                }
            }
            availableP11LibraryToAliasMap = ret;
        }
        return availableP11LibraryToAliasMap;
    }
    
    private static Map<String,String> availableP11AttributeFiles = null;
    /** @return a (cached) mapping between the PKCS#11 attribute files and their display names */
    public static Map<String,String> getAvailableP11AttributeFiles() {
        if (availableP11AttributeFiles==null) {
            final Map<String,String> ret = new HashMap<String,String>();
            for (int i=0; i<256; i++) {
                String fileName = EjbcaConfigurationHolder.getString("cryptotoken.p11.attr." + i + ".file");
                if (fileName!=null) {
                    String displayName = EjbcaConfigurationHolder.getString("cryptotoken.p11.attr." + i + ".name");
                    final File file = new File(fileName);
                    if (file.exists()) {
                        fileName = file.getAbsolutePath();
                        if (displayName == null || displayName.length()==0) {
                            displayName = fileName;
                        }
                        ret.put(fileName, displayName);
                    }
                }
            }
            availableP11AttributeFiles = ret;
        }
        return availableP11AttributeFiles;
    }

    public static String getStatedumpTemplatesBasedir() {
        return EjbcaConfigurationHolder.getString("statedump.templatebasedir");
    }
    
    /** Returns true if the CRL Store Servlet (search.cgi) is enabled. Default is false */
    public static boolean isCrlStoreEnabled() {
        return Boolean.valueOf(EjbcaConfigurationHolder.getString("crlstore.enabled"));
    }
    
    /** Returns true if the Certificate Store Servlet (search.cgi) is enabled. Default is false */
    public static boolean isCertStoreEnabled() {
        return Boolean.valueOf(EjbcaConfigurationHolder.getString("certstore.enabled"));
    }
    
    /** Returns the base URL path of the CRL store servlet, e.g. /ejbca/publicweb/crls */ 
    public static String getCrlStoreContextRoot() {
        String value = EjbcaConfigurationHolder.getString("crlstore.contextroot");
        if (value == null) {
            value = "/crls";
        }
        return value;
    }
}
