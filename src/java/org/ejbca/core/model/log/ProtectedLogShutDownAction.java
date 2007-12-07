package org.ejbca.core.model.log;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;

/**
 * Kills the JVM.
 */
public class ProtectedLogShutDownAction implements IProtectedLogAction {

    private static final Logger log = Logger.getLogger(ProtectedLogScriptAction.class);
    private static final InternalResources intres = InternalResources.getInstance();

	public ProtectedLogShutDownAction(Properties properties) {
	}

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
