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

public class OldLogConfiguration {

	/**
	 * Use simple log singing
	 * @deprecated "protection.logprotect" in "protect.properties" instead. (Handled by org.ejbca.config.ProtectConfiguration.)
	 */
	public static boolean getLogSigning() {
		return "true".equalsIgnoreCase(ConfigurationHolder.getString("logSigning", "false"));
	}
}
