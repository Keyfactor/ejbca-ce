package org.ejbca.core.model.log;

import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Kills the JVM.
 */
public class ProtectedLogShutDownAction implements IProtectedLogAction {

    private static final Logger log = Logger.getLogger(ProtectedLogScriptAction.class);

	public ProtectedLogShutDownAction(Properties properties) {
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		if (!IProtectedLogAction.CAUSE_TESTING.equalsIgnoreCase(causeIdentifier)) {
			log.info("ProtectedLogShutDownAction is killing JVM now.. " + causeIdentifier);
			Runtime.getRuntime().halt(1);
		}
	}
}
