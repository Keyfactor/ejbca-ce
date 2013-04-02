package org.ejbca.config;

public class ScepConfiguration {
    
    public static final String SCEP_RA_CERTPROFILE = "scep.ra.certificateProfile";
    public static final String SCEP_RA_ENTITYPROFILE = "scep.ra.entityProfile";
    public static final String SCEP_RA_AUTHPWD = "scep.ra.authPwd";
    public static final String SCEP_RA_DEFAULTCA = "scep.ra.defaultCA";
    public static final String SCEP_CA = "scep.defaultca";
    public static final String SCEP_EDITUSER = "scep.ra.createOrEditUser";
    public static final String SCEP_RA_NAME_GENERATION_SCHEME = "scep.ra.namegenerationscheme";
    public static final String SCEP_RA_NAME_GENERATION_PARAMETERS = "scep.ra.namegenerationparameters";
    public static final String SCEP_RA_NAME_GENERATION_PREFIX = "scep.ra.namegenerationprefix";
    public static final String SCEP_RA_NAME_GENERATION_POSTFIX = "scep.ra.namegenerationpostfix";
    
    public static String getRACertProfile() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_CERTPROFILE);    }

    public static String getRAEndEntityProfile() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_ENTITYPROFILE);
    }
    
    public static String getRAAuthPwd() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_AUTHPWD);
    }
    
    public static String getRADefaultCA() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_DEFAULTCA);
    }
    
    public static String getSCEPDefaultCA() {
        return EjbcaConfigurationHolder.getString(SCEP_CA);
    }
    
    public static boolean getAddOrEditUser() {
        return "true".equalsIgnoreCase(EjbcaConfigurationHolder.getString(SCEP_EDITUSER));
    }
  
    public static String getRANameGenerationScheme() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_NAME_GENERATION_SCHEME);
    }
    
    public static String getRANameGenerationParameters() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_NAME_GENERATION_PARAMETERS);
    }
    
    public static String getRANameGenerationPrefix() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_NAME_GENERATION_PREFIX);
    }
    
    public static String getRANameGenerationPostfix() {
        return EjbcaConfigurationHolder.getString(SCEP_RA_NAME_GENERATION_POSTFIX);
    }
    
}
