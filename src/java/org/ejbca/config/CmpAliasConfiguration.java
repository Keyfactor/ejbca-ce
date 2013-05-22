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

public class CmpAliasConfiguration {
    
    public static final String CONFIG_PREFIX                  = "cmp.";
    public static final String CONFIG_DEFAULTCA               = ".defaultca";
    public static final String CONFIG_ALLOWRAVERIFYPOPO       = ".allowraverifypopo";
    public static final String CONFIG_ALLOWAUTOMATICKEYUPDATE = ".allowautomatickeyupdate";
    public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY  = ".allowupdatewithsamekey";
    public static final String CONFIG_OPERATIONMODE           = ".operationmode";
    public static final String CONFIG_AUTHENTICATIONMODULE    = ".authenticationmodule";
    public static final String CONFIG_AUTHENTICATIONPARAMETERS= ".authenticationparameters";
    public static final String CONFIG_EXTRACTUSERNAMECOMPONENT= ".extractusernamecomponent";
    public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO = ".ra.allowcustomcertserno";
    public static final String CONFIG_RA_NAMEGENERATIONSCHEME = ".ra.namegenerationscheme";
    public static final String CONFIG_RA_NAMEGENERATIONPARAMS = ".ra.namegenerationparameters";
    public static final String CONFIG_RA_AUTHENTICATIONSECRET = ".ra.authenticationsecret";
    public static final String CONFIG_RA_ENDENTITYPROFILE     = ".ra.endentityprofile";
    public static final String CONFIG_RA_CERTIFICATEPROFILE   = ".ra.certificateprofile";
    public static final String CONFIG_RESPONSEPROTECTION      = ".responseprotection";
    public static final String CONFIG_RACANAME                = ".ra.caname";
    public static final String CONFIG_CERTREQHANDLER_CLASS    = ".certreqhandler.class";
    public static final String CONFIG_UNIDDATASOURCE          = ".uniddatasource";
    public static final String CONFIG_VENDORCERTIFICATEMODE   = ".vendorcertificatemode"; 
    public static final String CONFIG_VENDORCA                = ".vendorca";
    public static final String CONFIG_RACERT_PATH             = ".racertificatepath";

    public static final String AUTHMODULE_REG_TOKEN_PWD         = "RegTokenPwd";
    public static final String AUTHMODULE_DN_PART_PWD           = "DnPartPwd";
    public static final String AUTHMODULE_HMAC                  = "HMAC";
    public static final String AUTHMODULE_ENDENTITY_CERTIFICATE = "EndEntityCertificate";
    
    /**
     * This defines if we allows messages that has a POPO setting of raVerify. 
     * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
     */
    public static boolean getAllowRAVerifyPOPO(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_ALLOWRAVERIFYPOPO;
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(prop));
    }

    /**
     * This defines if we allow automatic renewal of a certificate by setting the end entity status to "NEW" before requesting a new certificate
     * If this variable is set to false, the status of the end entity will not be altered before requesting a new certificate
     */
    public static boolean getAllowAutomaticKeyUpdate(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_ALLOWAUTOMATICKEYUPDATE;
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(prop));
    }

    /**
     * This defines if we allow the KeyUpdate (which is equivalent to certificate renewal) to be done using the same old keys
     */
     public static boolean getAllowUpdateWithSameKey(String alias) {
         String prop = CONFIG_PREFIX + alias + CONFIG_ALLOWUPDATEWITHSAMEKEY;
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(prop));
    }

    /**
     * The catalog containing the trusted certificates to be used to verify a NestedMessageContent 
     */
    public static String getRaCertificatePath(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RACERT_PATH;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    /** The default CA used for signing requests, if it is not given in the request itself. */
    public static String getDefaultCA(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_DEFAULTCA;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    /**
     * Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing.
     * Nothing means that the DN will be used to look up the user.
     */
    public static String getExtractUsernameComponent(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_EXTRACTUSERNAMECOMPONENT;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getAuthenticationModule(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_AUTHENTICATIONMODULE;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getAuthenticationParameters(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_AUTHENTICATIONPARAMETERS;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getAuthenticationParameter(String authModule, String alias) {
        
        String confModule = getAuthenticationModule(alias);
        String confParams = getAuthenticationParameters(alias);
        
        String modules[] = confModule.split(";");
        String params[] = confParams.split(";");
        
        for(int i=0; i<modules.length; i++) {
            if(StringUtils.equals(modules[i].trim(), authModule)) {
                return params[i];
            }
        }
        
        return "-";

    }
    
    public static boolean getRAOperationMode(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_OPERATIONMODE;
        return "ra".equalsIgnoreCase(EjbcaConfigurationHolder.getString(prop));
    }
    
    public static boolean getVendorCertificateMode(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_VENDORCERTIFICATEMODE;
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(prop));
    }
    
    public static String getVendorCA(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_VENDORCA;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRANameGenerationScheme(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RA_NAMEGENERATIONSCHEME;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRANameGenerationParameters(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RA_NAMEGENERATIONPARAMS;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRANameGenerationPrefix(String alias) {
        String prop = CONFIG_PREFIX + alias + ".ra.namegenerationprefix";
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRANameGenerationPostfix(String alias) {
        String prop = CONFIG_PREFIX + alias + ".ra.namegenerationpostfix";
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getUserPasswordParams(String alias) {
        String prop = CONFIG_PREFIX + alias + ".ra.passwordgenparams";
        return EjbcaConfigurationHolder.getString(prop);      
    }
    
    public static String getRAAuthenticationSecret(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RA_AUTHENTICATIONSECRET;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRAEndEntityProfile(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RA_ENDENTITYPROFILE;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRACertificateProfile(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RA_CERTIFICATEPROFILE;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getRACAName(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RACANAME;
        return EjbcaConfigurationHolder.getString(prop);
    }
    
    public static String getResponseProtection(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RESPONSEPROTECTION;
        return EjbcaConfigurationHolder.getString(prop);
    }
        
    public static boolean getRAAllowCustomCertSerno(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_RA_ALLOWCUSTOMCERTSERNO;
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(prop));
    }

    public static String getUnidDataSource(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_UNIDDATASOURCE;
        return EjbcaConfigurationHolder.getString(prop);
    }

    public static String getCertReqHandlerClass(String alias) {
        String prop = CONFIG_PREFIX + alias + CONFIG_CERTREQHANDLER_CLASS;
        return EjbcaConfigurationHolder.getString(prop);
    }
}
