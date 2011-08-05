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

package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Collection;

import org.cesecore.authentication.tokens.AuthenticationToken;

/** This interface is used for exporting a number of log entries to 
 * any format defined by the implementing class.
 * 
 * @version $Id$
 */
public interface ILogExporter extends Serializable {

	/** Returns the exported data, determined by the exporting class. Can be binary or text data.
	 * @param logentries the log entries that will be exported
	 * @throws Exception if an error occurs during export
	 * @return byte data or null if no of exported entries are 0.
	 */
	public byte[] export(AuthenticationToken admin, Collection<LogEntry> logentries) throws Exception;

}

