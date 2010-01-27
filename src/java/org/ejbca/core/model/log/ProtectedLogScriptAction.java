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
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.model.InternalResources;

/**
 * Runs an executable with the error code as argument. 
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogScriptAction implements IProtectedLogAction, Serializable {

	private static final long serialVersionUID = -7056505975194222538L;

	/** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    private static final Logger log = Logger.getLogger(ProtectedLogScriptAction.class);

	private static final String SCRIPTACTION_ERROR_FAILED       = "protectedlog.safailed";
	private static final String SCRIPTACTION_ERROR_NOTARGET     = "protectedlog.sanotarget";
	private static final String SCRIPTACTION_ERROR_ERRORCODE    = "protectedlog.saerrorcode";
	
	private String targetScript = ProtectedLogConfiguration.getScriptActionScript();

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		if (log.isTraceEnabled()) {
			log.trace(">action " + causeIdentifier);
		}
		if (targetScript == null) {
			log.error(intres.getLocalizedMessage(SCRIPTACTION_ERROR_NOTARGET));
			return;
		}
		try {
			Process externalProcess = Runtime.getRuntime().exec( targetScript + " " + causeIdentifier + " "
					+ intres.getLocalizedMessage(causeIdentifier));
			// Check errorcode 
			if ( externalProcess.waitFor() != 0 ) {
				log.error(intres.getLocalizedMessage(SCRIPTACTION_ERROR_ERRORCODE));
			}
		} catch (Exception e) {
			log.error(intres.getLocalizedMessage(SCRIPTACTION_ERROR_FAILED));
		}
	}
}
