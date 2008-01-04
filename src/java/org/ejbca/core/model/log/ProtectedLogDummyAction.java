package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Properties;

/**
 * Dummy implentation. This is the simplest possible (and most useless) implementation.
 */
public class ProtectedLogDummyAction implements IProtectedLogAction, Serializable {

	private static final long serialVersionUID = -7056505975194222537L;

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
