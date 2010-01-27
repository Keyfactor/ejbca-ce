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

import org.apache.log4j.Logger;

/**
 * Dummy implementation. This is the simplest possible (and most useless) implementation.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogDummyExportHandler implements IProtectedLogExportHandler, Serializable {

	private static final Logger log = Logger.getLogger(ProtectedLogDummyExportHandler.class);

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public void init(long exportEndTime, long exportStartTime, boolean forced) {
		log.info("Export initialized for interval " + exportStartTime + " - " + exportEndTime + ".");
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public boolean done(String currentHashAlgorithm, byte[] exportedHash, byte[] lastExportedHash) {
		log.info("Export to console finished..");
		return true;
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public boolean update(int adminType, String admindata, int caid, int module, long eventTime, String username, String certificateSerialNumber, String certificateIssuerDN, int eventId, String eventComment) {
		log.info("Export update to console: "+eventTime + " " + eventComment);
		return true;
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public void abort() {
		log.info("Export aborted.");
	}
}
