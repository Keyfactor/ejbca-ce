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
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectedLogConfiguration;

/**
 * Invokes configured actions.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogActions implements Serializable {

	private static final long serialVersionUID = -7056505975194222535L;

    private static final Logger log = Logger.getLogger(ProtectedLogActions.class);

	private ArrayList actions = null;	// <IProtectedLogAction>
	
	private ProtectedLogActions() {}

	/**
	 * @param enableActions will load actions based on current configuration if true
	 */
	public ProtectedLogActions(int actionType) {
		if (actions == null) {
			actions = new ArrayList();	
			switch (actionType) {
			case ProtectedLogConstants.ACTION_TEST:
				actions.add(new ProtectedLogTestAction());
				break;
			case ProtectedLogConstants.ACTION_ALL:
				if (ProtectedLogConfiguration.getUseDummyAction()) {
					log.debug("adding DummyAction");
					actions.add(new ProtectedLogDummyAction());
				}
				if (ProtectedLogConfiguration.getUseScriptAction()) {
					log.debug("adding ScriptAction");
					actions.add(new ProtectedLogScriptAction());
				}
				if (ProtectedLogConfiguration.getUseMailAction()) {
					log.debug("adding MailAction");
					actions.add(new ProtectedLogMailAction());
				}
				if (ProtectedLogConfiguration.getUseShutDownAction()) {
					log.debug("adding ShutDownAction");
					actions.add(new ProtectedLogShutDownAction());
				}
				if (ProtectedLogConfiguration.getUseTestAction()) {
					log.debug("adding TestAction");
					actions.add(new ProtectedLogTestAction());
				}
				break;
			case ProtectedLogConstants.ACTION_NONE:
			default:
				break;
			}
		}
	}
	
	/**
	 * @param actionIdentifier is one of the IProtectedLogAction.CAUSE_* constants.
	 */
	public void takeActions(String actionIdentifier) {
		if (log.isDebugEnabled()) {
			log.debug("takeActions: "+actionIdentifier); 
		}
		Iterator i = actions.iterator();
        while (i.hasNext()) {
            ((IProtectedLogAction) i.next()).action(actionIdentifier);
        }
	}


}
