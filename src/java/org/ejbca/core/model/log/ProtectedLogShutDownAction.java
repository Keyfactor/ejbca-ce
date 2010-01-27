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
import org.ejbca.core.model.InternalResources;

/**
 * Kills the JVM.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogShutDownAction implements IProtectedLogAction, Serializable {

	private static final long serialVersionUID = -7056505975194222540L;

    private static final Logger log = Logger.getLogger(ProtectedLogScriptAction.class);
    private static final InternalResources intres = InternalResources.getInstance();

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		if (!IProtectedLogAction.CAUSE_TESTING.equalsIgnoreCase(causeIdentifier)) {
	    	log.info(intres.getLocalizedMessage("protectedlog.sda.killingjvm"));
			Runtime.getRuntime().halt(1);
		}
	}
}
