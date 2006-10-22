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


/** A Jboss service that has a lot of configuration options for CMP operations
 * 
 * version $Id: CmpTcpServiceMBean.java,v 1.2 2006-10-22 09:04:49 anatom Exp $
*/
public interface CmpTcpServiceMBean extends org.jboss.system.ServiceMBean
{   
	public String getOperationMode();

	public void setOperationMode(String operationMode);
	
	public String getAllowRaVerifyPopo();

	public void setAllowRaVerifyPopo(String allowRaVerifyPopo);

	public String getCaName();

	public void setCaName(String caName);

	public String getCertProfile();

	public void setCertProfile(String certProfile);

	public String getDefaultCA();

	public void setDefaultCA(String defaultCA);

	public String getRaModeNameGenerationScheme();

	public void setRaModeNameGenerationScheme(String generatorComponent);

	public String getEeProfile();

	public void setEeProfile(String eeProfile);

	public String getExtractUsernameComponent();

	public void setExtractUsernameComponent(String extractUsernameComponent);

	public String getRaNameGenerationParameters();

	public void setRaNameGenerationParameters(String mode);

	public String getPostfix();

	public void setPostfix(String postfix);

	public String getPrefix();

	public void setPrefix(String prefix);

	public String getResponseProtection();
	
	public void setResponseProtection(String responseProtection);

	public String getRaAuthenticationSecret();

	public void setRaAuthenticationSecret(String raAuthenticationSecret);

	public String getPortNo();
	
	public void setPortNo(String portNo);
	
	public String getLogDir();
	
	public void setLogDir(String logDir);

	public String getConfFile();
	
	public void setConfFile(String confFile);


}
