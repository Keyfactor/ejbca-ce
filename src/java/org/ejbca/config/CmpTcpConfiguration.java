package org.ejbca.config;

public class CmpTcpConfiguration {
    
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
}






/*
import org.apache.commons.lang.StringUtils;

public class CmpConfiguration {
    
    public static final String CONFIG_DEFAULTCA               = "cmp.defaultca";
    public static final String CONFIG_ALLOWRAVERIFYPOPO       = "cmp.allowraverifypopo";
    public static final String CONFIG_ALLOWAUTOMATICKEYUPDATE = "cmp.allowautomatickeyupdate";
    public static final String CONFIG_ALLOWUPDATEWITHSAMEKEY  = "cmp.allowupdatewithsamekey";
    public static final String CONFIG_OPERATIONMODE           = "cmp.operationmode";
    public static final String CONFIG_AUTHENTICATIONMODULE    = "cmp.authenticationmodule";
    public static final String CONFIG_AUTHENTICATIONPARAMETERS= "cmp.authenticationparameters";
    public static final String CONFIG_EXTRACTUSERNAMECOMPONENT= "cmp.extractusernamecomponent";
    public static final String CONFIG_RA_ALLOWCUSTOMCERTSERNO = "cmp.ra.allowcustomcertserno";
    public static final String CONFIG_RA_NAMEGENERATIONSCHEME = "cmp.ra.namegenerationscheme";
    public static final String CONFIG_RA_NAMEGENERATIONPARAMS = "cmp.ra.namegenerationparameters";
    public static final String CONFIG_RA_AUTHENTICATIONSECRET = "cmp.ra.authenticationsecret";
    public static final String CONFIG_RA_ENDENTITYPROFILE     = "cmp.ra.endentityprofile";
    public static final String CONFIG_RA_CERTIFICATEPROFILE   = "cmp.ra.certificateprofile";
    public static final String CONFIG_RESPONSEPROTECTION      = "cmp.responseprotection";
    public static final String CONFIG_RACANAME                = "cmp.ra.caname";
    public static final String CONFIG_CERTREQHANDLER_CLASS    = "cmp.certreqhandler.class";
    public static final String CONFIG_UNIDDATASOURCE           = "cmp.uniddatasource";
    public static final String CONFIG_VENDORCERTIFICATEMODE    = "cmp.vendorcertificatemode"; 
    public static final String CONFIG_VENDORCA                 = "cmp.vendorca";

    public static final String CONFIG_RACERT_PATH             = "cmp.racertificatepath";

    public static final String AUTHMODULE_REG_TOKEN_PWD         = "RegTokenPwd";
    public static final String AUTHMODULE_DN_PART_PWD           = "DnPartPwd";
    public static final String AUTHMODULE_HMAC                  = "HMAC";
    public static final String AUTHMODULE_ENDENTITY_CERTIFICATE = "EndEntityCertificate";
    
    /**
     * This defines if we allows messages that has a POPO setting of raVerify. 
     * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
     * /
    public static boolean getAllowRAVerifyPOPO(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWRAVERIFYPOPO));
        } else {
            return CmpAliasConfiguration.getAllowRAVerifyPOPO(alias);
        }
    }

    /**
     * This defines if we allow automatic renewal of a certificate by setting the end entity status to "NEW" before requesting a new certificate
     * If this variable is set to false, the status of the end entity will not be altered before requesting a new certificate
     * /
    public static boolean getAllowAutomaticKeyUpdate(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWAUTOMATICKEYUPDATE));
        } else {
            return CmpAliasConfiguration.getAllowAutomaticKeyUpdate(alias);
        }
    }

    /**
     * This defines if we allow the KeyUpdate (which is equivalent to certificate renewal) to be done using the same old keys
     * /
     public static boolean getAllowUpdateWithSameKey(String alias) {
         if(StringUtils.isEmpty(alias)) {
             return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getExpandedString(CONFIG_ALLOWUPDATEWITHSAMEKEY));
         } else {
             return CmpAliasConfiguration.getAllowUpdateWithSameKey(alias);
         }
    }

    /**
     * The catalog containing the trusted certificates to be used to verify a NestedMessageContent 
     * /
    public static String getRaCertificatePath(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RACERT_PATH);
        } else {
            return CmpAliasConfiguration.getRaCertificatePath(alias);
        }
    }
    
    /** The default CA used for signing requests, if it is not given in the request itself. * /
    public static String getDefaultCA(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_DEFAULTCA);
        } else {
            return CmpAliasConfiguration.getDefaultCA(alias);
        }
    }
    
    /**
     * Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing.
     * Nothing means that the DN will be used to look up the user.
     * /
    public static String getExtractUsernameComponent(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_EXTRACTUSERNAMECOMPONENT);
        } else {
            return CmpAliasConfiguration.getExtractUsernameComponent(alias);
        }
    }
    
    public static String getAuthenticationModule(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_AUTHENTICATIONMODULE);
        } else {
            return CmpAliasConfiguration.getAuthenticationModule(alias);
        }
    }
    
    public static String getAuthenticationParameters(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_AUTHENTICATIONPARAMETERS);
        } else {
            return CmpAliasConfiguration.getAuthenticationParameters(alias);
        }
    }
    
    public static String getAuthenticationParameter(String authModule, String alias) {

        if(StringUtils.isEmpty(alias)) {
            String confModule = getAuthenticationModule(null);
            String confParams = getAuthenticationParameters(null);
        
            String modules[] = confModule.split(";");
            String params[] = confParams.split(";");
        
            for(int i=0; i<modules.length; i++) {
                if(StringUtils.equals(modules[i].trim(), authModule)) {
                    return params[i];
                }
            }
        
            return "-";
        } else {
            return CmpAliasConfiguration.getAuthenticationParameter(authModule, alias);
        }

    }
    
    public static boolean getRAOperationMode(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return "ra".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_OPERATIONMODE));
        } else {
            return CmpAliasConfiguration.getRAOperationMode(alias);
        }
    }
    
    public static boolean getVendorCertificateMode(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_VENDORCERTIFICATEMODE));
        } else {
            return CmpAliasConfiguration.getVendorCertificateMode(alias);
        }
    }
    
    public static String getVendorCA(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_VENDORCA);
        } else {
            return CmpAliasConfiguration.getVendorCA(alias);
        }
    }
    
    public static String getRANameGenerationScheme(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RA_NAMEGENERATIONSCHEME);
        } else {
            return CmpAliasConfiguration.getRANameGenerationScheme(alias);
        }
    }
    
    public static String getRANameGenerationParameters(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RA_NAMEGENERATIONPARAMS);
        } else {
            return CmpAliasConfiguration.getRANameGenerationParameters(alias);
        }
    }
    
    public static String getRANameGenerationPrefix(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString("cmp.ra.namegenerationprefix");
        } else {
            return CmpAliasConfiguration.getRANameGenerationPrefix(alias);
        }
    }
    
    public static String getRANameGenerationPostfix(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString("cmp.ra.namegenerationpostfix");
        } else {
            return CmpAliasConfiguration.getRANameGenerationPostfix(alias);
        }
    }
    
    public static String getUserPasswordParams(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString("cmp.ra.passwordgenparams");
        } else {
            return CmpAliasConfiguration.getUserPasswordParams(alias);
        }
    }
    
    public static String getRAAuthenticationSecret(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RA_AUTHENTICATIONSECRET);
        } else {
            return CmpAliasConfiguration.getRAAuthenticationSecret(alias);
        }
    }
    
    public static String getRAEndEntityProfile(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RA_ENDENTITYPROFILE);
        } else {
            return CmpAliasConfiguration.getRAEndEntityProfile(alias);
        }
    }
    
    public static String getRACertificateProfile(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RA_CERTIFICATEPROFILE);
        } else {
            return CmpAliasConfiguration.getRACertificateProfile(alias);
        }
    }
    
    public static String getRACAName(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RACANAME);
        } else {
            return CmpAliasConfiguration.getRACAName(alias);
        }
    }
    
    public static String getResponseProtection(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_RESPONSEPROTECTION);
        } else {
            return CmpAliasConfiguration.getResponseProtection(alias);
        }
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
    
    public static boolean getRAAllowCustomCertSerno(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(CONFIG_RA_ALLOWCUSTOMCERTSERNO));
        } else {
            return CmpAliasConfiguration.getRAAllowCustomCertSerno(alias);
        }
    }

    public static String getUnidDataSource(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_UNIDDATASOURCE);
        } else {
            return CmpAliasConfiguration.getUnidDataSource(alias);
        }
    }

    public static String getCertReqHandlerClass(String alias) {
        if(StringUtils.isEmpty(alias)) {
            return EjbcaConfigurationHolder.getString(CONFIG_CERTREQHANDLER_CLASS);
        } else {
            return CmpAliasConfiguration.getCertReqHandlerClass(alias);
        }
    }
}
*/