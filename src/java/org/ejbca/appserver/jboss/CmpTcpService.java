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

package org.ejbca.appserver.jboss;

import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.ejbca.ui.tcp.CmpTcpConfiguration;
import org.ejbca.ui.tcp.CmpTcpServer;
import org.jboss.system.ServiceMBeanSupport;

/** 
 * An MBean service managing listening for cmp messages over tcp.
 */
public class CmpTcpService extends ServiceMBeanSupport implements CmpTcpServiceMBean
{ 
	
	/** This defines if we allows messages that has a POPO setting of raVerify. 
	 * If this variable is true, and raVerify is the POPO defined in the message, no POPO check will be done.
	 */
	private String allowRaVerifyPopo = "false";
	/** The default CA used for signing requests, if it is not given in the request itself. */
	private String defaultCA = null;
	/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
	private String extractUsernameComponent = null;
	
	/** The operation mode, RA or NORMAL */
	private String operationMode = "normal";
	/** The endEntityProfile to be used when adding users in RA mode */
	private String eeProfile = "EMTPTY";
	/** The certificate profile to use when adding users in RA mode */
	private String certProfile = "ENDUSER";
	/** Tha CA to user when adding users in RA mode */
	private String caName = "AdminCA1";
	/** Parameter used to authenticate RA messages if we are using RA mode to create users */
	private String raAuthenticationSecret = null;

	private String raNameGenerationParameters = "CN"; // Can be CN or UID
	private String raModeNameGenerationScheme = "DN"; 
	private String prefix = null;
	private String postfix = null;
	
	private String portNo = "829";
	private String logDir = "./log";
	private String confFile = "";
	
	public String getName()
	{
		return "CmpTcpService";      
	}
	
	public void startService() throws Exception
	{
		Properties properties = new Properties();
		String str = getAllowRaVerifyPopo();
		if (StringUtils.equals("true", str)) {
			log.debug("allowRAVerifyPopo=true");
			properties.setProperty("allowRaVerifyPopo", "true");
		}
		str = getDefaultCA();
		log.debug("defaultCA="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("defaultCA", str);
		}
		str = getExtractUsernameComponent();
		log.debug("extractUsernameComponent="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("extractUsernameComponent", str);
		}
		str = getOperationMode();
		log.debug("operationMode="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("operationMode", str);
		}
		str = getRaModeNameGenerationScheme();
		log.debug("raModeNameGenerationScheme="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("raModeNameGenerationScheme", str);
		}
		str = getRaNameGenerationParameters();
		log.debug("raModeNameGenerationParameters="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("raModeNameGenerationParameters", str);
		}
		str = getPrefix();
		log.debug("raModeNameGenerationPrefix="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("raModeNameGenerationPrefix", str);
		}
		str = getPostfix();
		log.debug("raModeNameGenerationPostfix="+str);
		if (StringUtils.isNotEmpty(str)) {
			properties.setProperty("raModeNameGenerationPostfix", str);
		}
		str = getRaAuthenticationSecret();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("raAuthenticationSecret is not null");
			properties.setProperty("raAuthenticationSecret", str);
		}
		str = getEeProfile();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("endEntityProfile="+str);
			properties.setProperty("endEntityProfile", str);
		}			
		str = getCertProfile();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("certificateProfile="+str);
			properties.setProperty("certificateProfile", str);
		}
		str = getCaName();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("caName="+str);
			properties.setProperty("caName", str);
		}			
		str = getPortNo();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("portNo="+str);
			properties.setProperty("portNo", str);
		}			
		str = getLogDir();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("logDir="+str);
			properties.setProperty("logDir", str);
		}			
		str = getConfFile();
		if (StringUtils.isNotEmpty(str)) {
			log.debug("confFile="+str);
			properties.setProperty("confFile", str);
		}			
		
		CmpTcpConfiguration.instance().init(properties);
		CmpTcpServer.start();
	}
	
	public void stopService()
	{
		CmpTcpServer.stop();
	}

	public String getAllowRaVerifyPopo() {
		return allowRaVerifyPopo;
	}

	public void setAllowRaVerifyPopo(String allowRaVerifyPopo) {
		this.allowRaVerifyPopo = allowRaVerifyPopo;
	}

	public String getCaName() {
		return caName;
	}

	public void setCaName(String caName) {
		this.caName = caName;
	}

	public String getCertProfile() {
		return certProfile;
	}

	public void setCertProfile(String certProfile) {
		this.certProfile = certProfile;
	}

	public String getDefaultCA() {
		return defaultCA;
	}

	public void setDefaultCA(String defaultCA) {
		this.defaultCA = defaultCA;
	}

	public String getRaModeNameGenerationScheme() {
		return raModeNameGenerationScheme;
	}

	public void setRaModeNameGenerationScheme(String generatorComponent) {
		raModeNameGenerationScheme = generatorComponent;
	}

	public String getEeProfile() {
		return eeProfile;
	}

	public void setEeProfile(String eeProfile) {
		this.eeProfile = eeProfile;
	}

	public String getExtractUsernameComponent() {
		return extractUsernameComponent;
	}

	public void setExtractUsernameComponent(String extractUsernameComponent) {
		this.extractUsernameComponent = extractUsernameComponent;
	}

	public String getRaNameGenerationParameters() {
		return raNameGenerationParameters;
	}

	public void setRaNameGenerationParameters(String mode) {
		this.raNameGenerationParameters = mode;
	}

	public String getPostfix() {
		return postfix;
	}

	public void setPostfix(String postfix) {
		this.postfix = postfix;
	}

	public String getPrefix() {
		return prefix;
	}

	public void setPrefix(String prefix) {
		this.prefix = prefix;
	}

	public String getRaAuthenticationSecret() {
		return raAuthenticationSecret;
	}

	public void setRaAuthenticationSecret(String raAuthenticationSecret) {
		this.raAuthenticationSecret = raAuthenticationSecret;
	}

	public String getOperationMode() {
		return operationMode;
	}

	public void setOperationMode(String operationMode) {
		this.operationMode = operationMode;
	}
	public String getPortNo() {
		return portNo;
	}
	
	public void setPortNo(String port) {
		this.portNo = port;
	}
	
	public String getLogDir() {
		return logDir;
	}
	
	public void setLogDir(String dir) {
		this.logDir = dir;
	}

	public String getConfFile() {
		return this.confFile;
	}
	
	public void setConfFile(String file) {
		this.confFile = file;
	}

	
}