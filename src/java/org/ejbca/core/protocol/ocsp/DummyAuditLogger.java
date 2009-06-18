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

package org.ejbca.core.protocol.ocsp;

/**
 * This class ignores all input.
 */
public class DummyAuditLogger implements IAuditLogger {

	public void flush(String s) { }
	public void paramPut(String key, byte[] value) { }
	public void paramPut(String key, String value) { }
	public void paramPut(String key, Integer value) { }
	public void writeln() { }

}
