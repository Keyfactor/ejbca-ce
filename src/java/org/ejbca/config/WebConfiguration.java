package org.ejbca.config;

public class WebConfiguration {

	public static boolean getRequireAdminCertificateInDatabase() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getExpandedString("web.reqcertindb", "true"));
	}

	public static String getMailMimeType(){
	   	return "text/plain;charset=" + ConfigurationHolder.getString ("web.contentencoding", "UTF-8");
	}

}
