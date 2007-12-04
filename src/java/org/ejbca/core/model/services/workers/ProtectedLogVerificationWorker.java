package org.ejbca.core.model.services.workers;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.ProtectedLogVerifier;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;

public class ProtectedLogVerificationWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(ProtectedLogVerificationWorker.class);
	
	public static final String DEFAULT_SERVICE_NAME = "__ProtectedLogVerificationService__";
	public static final String CONF_VERIFICATION_INTERVAL = "verificationservice.invokationinterval";
	public static final String DEFAULT_VERIFICATION_INTERVAL = "1";

	public void work() throws ServiceExecutionFailedException {
		log.debug(">ProtectedLogVerificationWorker.work");
		ProtectedLogVerifier protectedLogVerifier = ProtectedLogVerifier.instance(properties);
		protectedLogVerifier.runIfNotBusy();
		log.debug("<ProtectedLogVerificationWorker done");
	}
	
}
