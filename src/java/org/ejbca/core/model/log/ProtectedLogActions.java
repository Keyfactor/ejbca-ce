package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

/**
 * Invokes configured actions.
 */
public class ProtectedLogActions implements Serializable {

	private ArrayList actions = new ArrayList();	// <IProtectedLogAction>

	public ProtectedLogActions(Properties properties) {
		if (properties != null) {
			// Setup Action classes.
			if (properties.getProperty("useDummyAction", "false").equalsIgnoreCase("true")) {
				actions.add(new ProtectedLogDummyAction(properties));
			}
			if (properties.getProperty("useScriptAction", "false").equalsIgnoreCase("true")) {
				actions.add(new ProtectedLogScriptAction(properties));
			}
			if (properties.getProperty("useMailAction", "false").equalsIgnoreCase("true")) {
				actions.add(new ProtectedLogMailAction(properties));
			}
			if (properties.getProperty("useShutDownAction", "false").equalsIgnoreCase("true")) {
				actions.add(new ProtectedLogShutDownAction(properties));
			}
		}
	}
	
	/**
	 * @param actionIdentifier is one of the IProtectedLogAction.CAUSE_* constants.
	 */
	public void takeActions(String actionIdentifier) {
		Iterator i = actions.iterator();
        while (i.hasNext()) {
            ((IProtectedLogAction) i.next()).action(actionIdentifier);
        }
	}


}
