package org.ejbca.config;

public class CmpConfiguration {

	public static boolean getAllowRAVerifyPOPO() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("cmp.allowraverifypopo", "false"));
	}
	
	public static String getDefaultCA() {
		return ConfigurationHolder.getString("cmp.defaultca", null);
	}
	
	public static String getExtractUsernameComponent() {
		return ConfigurationHolder.getString("cmp.extractusernamecomponent", null);
	}
	
	public static boolean getRAOperationMode() {
		return "ra".equalsIgnoreCase(ConfigurationHolder.getString("cmp.operationmode", "normal"));
	}
	
	public static String getRANameGenerationScheme() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationscheme", "DN");
	}
	
	public static String getRANameGenerationParameters() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationparameters", "CN");
	}
	
	public static String getRANameGenerationPrefix() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationprefix", null);
	}
	
	public static String getRANameGenerationPostfix() {
		return ConfigurationHolder.getString("cmp.ra.namegenerationpostfix", null);
	}
	
	public static String getUserPasswordParams() {
		return ConfigurationHolder.getString("cmp.ra.passwordgenparams", "random");		
	}
	
	public static String getRAAuthenticationSecret() {
		return ConfigurationHolder.getString("cmp.ra.authenticationsecret", null);
	}
	
	public static String getRAEndEntityProfile() {
		return ConfigurationHolder.getString("cmp.ra.endentityprofile", "EMPTY");
	}
	
	public static String getRACertificateProfile() {
		return ConfigurationHolder.getString("cmp.ra.certificateprofile", "ENDUSER");
	}
	
	public static String getRACAName() {
		return ConfigurationHolder.getString("cmp.ra.caname", "AdminCA1");
	}
	
	public static String getResponseProtection() {
		return ConfigurationHolder.getString("cmp.responseprotection", "signature");
	}
	
	public static int getTCPPortNumber() {
		return new Integer(ConfigurationHolder.getString("cmp.tcp.portno", "829")).intValue();
	}
	
	public static String getTCPLogDir() {
		return ConfigurationHolder.getString("cmp.tcp.logdir", "./log");
	}
	
	public static String getTCPConfigFile() {
		return ConfigurationHolder.getString("cmp.tcp.conffile", "");
	}
	
	public static String getTCPBindAdress() {
		return ConfigurationHolder.getString("cmp.tcp.bindadress", "0.0.0.0");
	}
	
	
}
