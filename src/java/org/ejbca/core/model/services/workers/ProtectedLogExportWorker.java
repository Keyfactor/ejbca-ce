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
package org.ejbca.core.model.services.workers;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.ProtectedLogExporter;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;


/**
 * EJBCA Service wrapper for ProtectedLogExporter to run as a worker.
 * @version $Id$
 *
 */
public class ProtectedLogExportWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(ProtectedLogExportWorker.class);
	
	public static final String DEFAULT_SERVICE_NAME = "__ProtectedLogExportService__";

	public void work() throws ServiceExecutionFailedException {
		log.trace(">ProtectedLogExportWorker.work");
		ProtectedLogExporter protectedLogExporter = ProtectedLogExporter.instance();
		protectedLogExporter.runIfNotBusy();
		log.trace("<ProtectedLogExportWorker done");
	}

}
