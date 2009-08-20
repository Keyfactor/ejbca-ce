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
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Invokes configured actions.
 * @version $Id$
 */
public class ProtectedLogActions implements Serializable {

	private static final long serialVersionUID = -7056505975194222535L;

    private static final Logger log = Logger.getLogger(ProtectedLogActions.class);

	public final static String CONF_USE_TESTACTION = "useTestAction";
	
	private ArrayList actions = new ArrayList();	// <IProtectedLogAction>

	public ProtectedLogActions(Properties properties) {
		if (properties != null) {
			// Setup Action classes.
			if (properties.getProperty("useDummyAction", "false").equalsIgnoreCase("true")) {
				log.debug("adding DummyAction");
				actions.add(new ProtectedLogDummyAction(properties));
			}
			if (properties.getProperty("useScriptAction", "false").equalsIgnoreCase("true")) {
				log.debug("adding ScriptAction");
				actions.add(new ProtectedLogScriptAction(properties));
			}
			if (properties.getProperty("useMailAction", "false").equalsIgnoreCase("true")) {
				log.debug("adding MailAction");
				actions.add(new ProtectedLogMailAction(properties));
			}
			if (properties.getProperty("useShutDownAction", "false").equalsIgnoreCase("true")) {
				log.debug("adding ShutDownAction");
				actions.add(new ProtectedLogShutDownAction(properties));
			}
			if (properties.getProperty(CONF_USE_TESTACTION, "false").equalsIgnoreCase("true")) {
				log.debug("adding TestAction");
				actions.add(new ProtectedLogTestAction(properties));
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
