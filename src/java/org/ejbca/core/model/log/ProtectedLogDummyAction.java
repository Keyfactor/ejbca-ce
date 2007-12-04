package org.ejbca.core.model.log;

import java.util.Properties;

/**
 * Dummy implentation. This is the simplest possible (and most useless) implementation.
 */
public class ProtectedLogDummyAction implements IProtectedLogAction {

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public ProtectedLogDummyAction(Properties properties) {
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		// Does nothing
	}

}
