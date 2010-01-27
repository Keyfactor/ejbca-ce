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


/**
 * An export handler is invoked when the export service s run.
 * 
 * It's not neccesary for the export handler to use the supplied parameters. but they are given
 * to simplify some exports.
 * @version $Id$
 * @deprecated
 */
public interface IProtectedLogExportHandler {

	/**
	 * The export handler should prepare to export the file.
	 * @param properties is passed on from the export service
	 * @param exportEndTime the time of the newest event that will be included in the export
	 * @param exportStartTime the time of the oldest event that will be included in the export
	 * @param forced is true if this is a recovery export and that the events are not verified
	 */
	void init(long exportEndTime, long exportStartTime, boolean forced);
	
	/**
	 * Called once for each verified log-event. 
	 * @return false if something went wrong
	 */
	boolean update(int adminType, String adminData, int caid, int module, long eventTime, String username,
			String certificateSerialNumber, String certificateIssuerDN, int eventId, String eventComment);

	/**
	 * Called to finalize the export.
	 * @param currentHashAlgorithm name of the hash algorithm used for calculating exportedHash  
	 * @param exportedHash is the calculated checksum of all event sent to update
	 * @param lastExportedHash is the calculated checksum of the last export
	 * @return
	 */
	boolean done(String currentHashAlgorithm, byte[] exportedHash, byte[] lastExportedHash);

	/**
	 * If something goes wrong during the export this method is called.
	 */
	void abort();

}
