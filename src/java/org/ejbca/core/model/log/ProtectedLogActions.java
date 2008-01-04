package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

/**
 * Invokes configured actions.
 */
public class ProtectedLogActions implements Serializable {

	private static final long serialVersionUID = -7056505975194222535L;
	
	public final static String CONF_USE_TESTACTION = "useTestAction";
	
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
			if (properties.getProperty(CONF_USE_TESTACTION, "false").equalsIgnoreCase("true")) {
				actions.add(new ProtectedLogTestAction(properties));
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
