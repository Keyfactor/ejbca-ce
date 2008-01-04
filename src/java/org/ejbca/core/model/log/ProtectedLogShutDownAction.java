package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;

/**
 * Kills the JVM.
 */
public class ProtectedLogShutDownAction implements IProtectedLogAction, Serializable {

	private static final long serialVersionUID = -7056505975194222540L;

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
