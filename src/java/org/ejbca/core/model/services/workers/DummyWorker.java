/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.Map;

import org.apache.log4j.Logger;
import org.ejbca.core.model.services.ActionException;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

/**
 * Dummy class used for demonstration and test puporses
 * Shows what is needed to create a custom worker
 *  
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id$
 */
public class DummyWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(DummyWorker.class);
	
	/**
	 * @see org.ejbca.core.model.services.IWorker#work()
	 */
	public void work(Map<Class<?>, Object> ejbs) throws ServiceExecutionFailedException {
		log.trace(">DummyWorker.work");
		try {
			log.info("DummyWorker executed");
			getAction().performAction(null, ejbs);
		} catch (ActionException e) {
		   // This should never happen
		}
		log.trace("<DummyWorker.work");
	}
}
