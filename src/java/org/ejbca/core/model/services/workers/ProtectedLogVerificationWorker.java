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
import org.ejbca.core.model.log.ProtectedLogVerifier;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * EJBCA Service wrapper for ProtectedLogVerifier to run as a worker.
 * @version $Id$
 *
 */
public class ProtectedLogVerificationWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(ProtectedLogVerificationWorker.class);
	
	public static final String DEFAULT_SERVICE_NAME = "__ProtectedLogVerificationService__";

	public void work() throws ServiceExecutionFailedException {
		log.trace(">ProtectedLogVerificationWorker.work");
		ProtectedLogVerifier protectedLogVerifier = ProtectedLogVerifier.instance();
		protectedLogVerifier.runIfNotBusy();
		log.trace("<ProtectedLogVerificationWorker done");
	}
	
}
