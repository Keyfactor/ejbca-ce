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

import org.ejbca.ui.tcp.CmpTcpServer;
import org.jboss.system.ServiceMBeanSupport;

/** 
 * An MBean service managing listening for cmp messages over tcp.
 */
public class CmpTcpService extends ServiceMBeanSupport implements CmpTcpServiceMBean { 
	
	public String getName() {
		return "CmpTcpService";      
	}
	
	public void startService() throws Exception {
		CmpTcpServer.start();
	}
	
	public void stopService() {
		CmpTcpServer.stop();
	}
}