/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
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

import org.apache.commons.lang.StringUtils;

public class CmpConfiguration {
	
	public static final String CONFIG_DEFAULTCA               = "cmp.defaultca";
	public static final String CONFIG_ALLOWRAVERIFYPOPO       = "cmp.allowraverifypopo";
	public static final String CONFIG_ALLOWAUTOMATICKEYUPDATE = "cmp.allowautomatickeyupdate";
    public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY  = "cmp.allowupdatewithsamekey";
	public static final String CONFIG_OPERATIONMODE           = "cmp.operationmode";
	public static final String CONFIG_AUTHENTICATIONMODULE	  = "cmp.authenticationmodule";
	public static final String CONFIG_AUTHENTICATIONPARAMETERS= "cmp.authenticationparameters";
	public static final String CONFIG_EXTRACTUSERNAMECOMPONENT= "cmp.extractusernamecomponent";
	public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO = "cmp.ra.allowcustomcertserno";
	public static final String CONFIG_RA_NAMEGENERATIONSCHEME = "cmp.ra.namegenerationscheme";
	public static final String CONFIG_RA_NAMEGENERATIONPARAMS = "cmp.ra.namegenerationparameters";
	public static final String CONFIG_RA_AUTHENTICATIONSECRET = "cmp.ra.authenticationsecret";
	public static final String CONFIG_RA_ENDENTITYPROFILE     = "cmp.ra.endentityprofile";
	public static final String CONFIG_RA_CERTIFICATEPROFILE   = "cmp.ra.certificateprofile";
	public static final String CONFIG_RESPONSEPROTECTION      = "cmp.responseprotection";
	public static final String CONFIG_RACANAME				  = "cmp.ra.caname";
	public static final String CONFIG_CERTREQHANDLER_CLASS    = "cmp.certreqhandler.class";
	public static final String CONFIG_UNIDDATASOURCE           = "cmp.uniddatasource";
	public static final String CONFIG_3GPPMODE                 = "cmp.3gppmode"; 
	public static final String CONFIG_3GPPCA                   = "cmp.3gppca";

    public static final String CONFIG_RACERT_PATH             = "cmp.racertificatepath";

	public static final String AUTHMODULE_REG_TOKEN_PWD         = "RegTokenPwd";
	public static final String AUTHMODULE_DN_PART_PWD           = "DnPartPwd";
	public static final String AUTHMODULE_HMAC                  = "HMAC";
	public static final String AUTHMODULE_ENDENTITY_CERTIFICATE = "EndEntityCertificate";
	
	/**
	 * This defines if we allows messages that has a POPO setting of raVerify. 
	 * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
	 */
	public static boolean getAllowRAVerifyPOPO() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWRAVERIFYPOPO));
    }

	/**
	 * This defines if we allow automatic renewal of a certificate by setting the end entity status to "NEW" before requesting a new certificate
	 * If this variable is set to false, the status of the end entity will not be altered before requesting a new certificate
	 */
	public static boolean getAllowAutomaticKeyUpdate() {
	    return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWAUTOMATICKEYUPDATE));
	}

    /**
     * This defines if we allow the KeyUpdate (which is equivalent to certificate renewal) to be done using the same old keys
     */
     public static boolean getAllowUpdateWithSameKey() {
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWUPDATEWITHSAMEKEY));
    }

	/**
	 * The catalog containing the trusted certificates to be used to verify a NestedMessageContent 
	 */
    public static String getRaCertificatePath() {
        return EjbcaConfigurationHolder.getString(CONFIG_RACERT_PATH);
	}
	
	/** The default CA used for signing requests, if it is not given in the request itself. */
	public static String getDefaultCA() {
		return EjbcaConfigurationHolder.getString(CONFIG_DEFAULTCA);
	}
	
	/**
	 * Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing.
	 * Nothing means that the DN will be used to look up the user.
	 */
	public static String getExtractUsernameComponent() {
		return EjbcaConfigurationHolder.getString(CONFIG_EXTRACTUSERNAMECOMPONENT);
	}
	
	public static String getAuthenticationModule() {
		return EjbcaConfigurationHolder.getString(CONFIG_AUTHENTICATIONMODULE);
	}
	
	public static String getAuthenticationParameters() {
		return EjbcaConfigurationHolder.getString(CONFIG_AUTHENTICATIONPARAMETERS);
	}
	
	public static String getAuthenticationParameter(String authModule) {
	    
	    String confModule = getAuthenticationModule();
	    String confParams = getAuthenticationParameters();
	    
	    String modules[] = confModule.split(";");
	    String params[] = confParams.split(";");
	    
	    for(int i=0; i<modules.length; i++) {
	        if(StringUtils.equals(modules[i].trim(), authModule)) {
	            return params[i];
	        }
	    }
	    
	    return "-";

	}
	
	public static boolean getRAOperationMode() {
		return "ra".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_OPERATIONMODE));
	}
	
	public static boolean get3GPPMode() {
	       return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_3GPPMODE));
	}
	
    public static String get3GPPCA() {
        return EjbcaConfigurationHolder.getString(CONFIG_3GPPCA);
    }
    
	public static String getRANameGenerationScheme() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_NAMEGENERATIONSCHEME);
	}
	
	public static String getRANameGenerationParameters() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_NAMEGENERATIONPARAMS);
	}
	
	public static String getRANameGenerationPrefix() {
		return EjbcaConfigurationHolder.getString("cmp.ra.namegenerationprefix");
	}
	
	public static String getRANameGenerationPostfix() {
		return EjbcaConfigurationHolder.getString("cmp.ra.namegenerationpostfix");
	}
	
	public static String getUserPasswordParams() {
		return EjbcaConfigurationHolder.getString("cmp.ra.passwordgenparams");		
	}
	
	public static String getRAAuthenticationSecret() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_AUTHENTICATIONSECRET);
	}
	
	public static String getRAEndEntityProfile() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_ENDENTITYPROFILE);
	}
	
	public static String getRACertificateProfile() {
		return EjbcaConfigurationHolder.getString(CONFIG_RA_CERTIFICATEPROFILE);
	}
	
	public static String getRACAName() {
		return EjbcaConfigurationHolder.getString(CONFIG_RACANAME);
	}
	
	public static String getResponseProtection() {
		return EjbcaConfigurationHolder.getString(CONFIG_RESPONSEPROTECTION);
	}
	
	public static int getTCPPortNumber() {
		return Integer.valueOf(EjbcaConfigurationHolder.getString("cmp.tcp.portno"));
	}
	
	public static String getTCPLogDir() {
		return EjbcaConfigurationHolder.getString("cmp.tcp.logdir");
	}
	
	public static String getTCPConfigFile() {
		return EjbcaConfigurationHolder.getString("cmp.tcp.conffile");
	}
	
	public static String getTCPBindAdress() {
		return EjbcaConfigurationHolder.getString("cmp.tcp.bindadress");
	}
	
	public static boolean getRAAllowCustomCertSerno() {
		return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_RA_ALLOWCUSTOMCERTSERNO));
	}

	public static String getUnidDataSource() {
		return EjbcaConfigurationHolder.getString(CONFIG_UNIDDATASOURCE);
	}

	public static String getCertReqHandlerClass() {
		return EjbcaConfigurationHolder.getString(CONFIG_CERTREQHANDLER_CLASS);
	}
}
