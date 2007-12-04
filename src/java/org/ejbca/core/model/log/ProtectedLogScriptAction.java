package org.ejbca.core.model.log;

import java.util.Properties;

import org.apache.log4j.Logger;
import org.ejbca.core.model.InternalResources;

/**
 * Runs an executable with the error code as argument. 
 */
public class ProtectedLogScriptAction implements IProtectedLogAction {

	/** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
    private static final Logger log = Logger.getLogger(ProtectedLogScriptAction.class);

	private static final String SCRIPTACTION_ERROR_FAILED				= "protectedlog.safailed";
	private static final String SCRIPTACTION_ERROR_NOTARGET		= "protectedlog.sanotarget";
	private static final String SCRIPTACTION_ERROR_ERRORCODE	= "protectedlog.saerrorcode";
	
	public static final String CONF_TARGET_SCRIPT = "scriptAction.target";
	private String targetScript = null;

	public ProtectedLogScriptAction(Properties properties) {
		targetScript = properties.getProperty(CONF_TARGET_SCRIPT); 
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogAction
	 */
	public void action(String causeIdentifier) {
		log.debug(">action " + causeIdentifier);
		if (targetScript == null || targetScript.equals("")) {
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
