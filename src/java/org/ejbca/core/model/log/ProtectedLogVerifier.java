package org.ejbca.core.model.log;

import java.util.Date;
import java.util.Properties;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.log.IProtectedLogSessionLocal;
import org.ejbca.core.ejb.log.IProtectedLogSessionLocalHome;

/**
 * Thread-safe singleton that invokes fowards a request from the verification service.  
 */
public class ProtectedLogVerifier {

	public static final String CONF_FREEZE_THRESHOLD = "verificationservice.freezetreshold";
	public static final String DEFAULT_FREEZE_THRESHOLD = "60";

	private IProtectedLogSessionLocal protectedLogSession = null;

	private static final Logger log = Logger.getLogger(ProtectedLogVerifier.class);
	
	private static ProtectedLogVerifier instance = null;
	
	private long timeOfLastExecution = 0;
	private long lastKnownEventTime = 0;
	private Properties properties = null;
	private boolean isRunning = false;
	private boolean isCanceled = false;
	private boolean isCanceledPermanently = false;
	long freezeThreshold = 0;
	long lastSuccessfulVerification = 0;

	private ProtectedLogActions protectedLogActions = null;
	
	private ProtectedLogVerifier(Properties properties) {
		this.properties = properties;
		freezeThreshold = Long.parseLong(properties.getProperty(CONF_FREEZE_THRESHOLD, DEFAULT_FREEZE_THRESHOLD)) * 60 * 1000;
		protectedLogActions = new ProtectedLogActions(properties);
	}
	
	/**
	 * Does not support update properties yet.
	 * @param properties
	 * @return
	 */
	public static ProtectedLogVerifier instance(Properties properties) {
		if (instance == null) {
			instance = new ProtectedLogVerifier(properties);
		}
		return instance;
	}
	
	/**
	 * @param properties
	 * @return null if not allocated.
	 */
	public static ProtectedLogVerifier instance() {
		return instance;
	}

	private IProtectedLogSessionLocal getProtectedLogSession() {
		try {
			if (protectedLogSession == null) {
				protectedLogSession = ((IProtectedLogSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IProtectedLogSessionLocalHome.COMP_NAME)).create();
			}
			return protectedLogSession;
		} catch (Exception e) {
			throw new EJBException(e);
		}
	}

	/**
	 * Runs all the verifications if it isn't busy from another caller.
	 */
	public void runIfNotBusy() {
		if (!isCanceledPermanently && getBusy()) {
			run();
		}
	}
	
	synchronized boolean getBusy() {
		if (isRunning) {
			return false;
		}
		return (isRunning = true);
	}
	
	public boolean isRunning() {
		return isRunning;
	}
	
	/**
	 * Inform the service next time it ask, that it is requested to stop.
	 */
	public void cancelVerification() {
		isCanceled = true;
	}
	
	/**
	 * Inform the service next time it ask, that it is requested to stop and don't start it again.
	 */
	public void cancelVerificationsPermanently() {
		isCanceledPermanently = true;
	}
	
	public boolean isCanceled() {
		return isCanceled || isCanceledPermanently;
	}

	/**
	 * @return the time in milliseconds of when the last successful verification began.
	 */
	public long getLastSuccessfulVerificationTime() {
		return lastSuccessfulVerification;
	}

	synchronized private void run() {
		log.debug(">run");
		long startTimeOfExecution = new Date().getTime();
		try  {
			ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
			// Verify that the log hasn't been emptied since last run
			// Verify that the log hasn't been rolled back since last run
			protectedLogEventIdentifier = verifyLastEvent();
			if (protectedLogEventIdentifier != null) {
				log.error("verifyLastEvent failed at NodeGUID " + protectedLogEventIdentifier.getNodeGUID() + " and counter " + protectedLogEventIdentifier.getCounter());
			} else {
				// Verify entire log
				// Verify that log hasn't been frozen for any node
				// Verify that each protect operation had a valid certificate and is not about to expire without a valid replacement
				try {
					protectedLogEventIdentifier = getProtectedLogSession().verifyEntireLog(protectedLogActions, freezeThreshold);	//verifyEntireLog();
					if (protectedLogEventIdentifier != null) {
						log.error("verifyEntireLog failed at NodeGUID " + protectedLogEventIdentifier.getNodeGUID() + " and counter " + protectedLogEventIdentifier.getCounter());
					} else {
						lastSuccessfulVerification = startTimeOfExecution;
					}
				} catch (Exception e) {
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
					log.error("Internal logging error.", e);
				}
			}
		} finally {
			timeOfLastExecution = startTimeOfExecution;
			isRunning = false;
			isCanceled = false;
		}
		log.debug("<run");
	}
	
	public long getTimeOfLastExecution() {
		return timeOfLastExecution;
	}
	
	/**
	 * Verify that the log hasn't been emptied since last run
	 * Verify that the log hasn't been rolled back since last run
	 */
	private ProtectedLogEventIdentifier verifyLastEvent() {
		log.debug(">verifyLastEvent");
		ProtectedLogActions protectedLogActions = new ProtectedLogActions(properties); 
		ProtectedLogEventIdentifier protectedLogEventIdentifier = getProtectedLogSession().findNewestProtectedLogEventRow();
		// Is log empy?
		if (protectedLogEventIdentifier == null) {
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_EMPTY_LOG);
			return protectedLogEventIdentifier;
		} else {
			// Has log been rolled back
			ProtectedLogEventRow protectedLogEventRow = getValidLogEventRow(protectedLogEventIdentifier);
			if (protectedLogEventRow != null) {
				// Compare time with last known event-time
				long currentEventTime = protectedLogEventRow.getEventTime();
				if (lastKnownEventTime > currentEventTime) {
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_ROLLED_BACK);
					return protectedLogEventIdentifier;
				}
				lastKnownEventTime = currentEventTime;
			}
		}
		log.debug("<verifyLastEvent");
		return null;
	}

	/**
	 * Retrieves and verifies the requested ProtectedLogEvent or null if not found.
	 */
	private ProtectedLogEventRow getValidLogEventRow(ProtectedLogEventIdentifier protectedLogEventIdentifier) {
		log.debug(">getValidLogEventRow");
		ProtectedLogEventRow protectedLogEventRow = getProtectedLogSession().getProtectedLogEventRow(protectedLogEventIdentifier);
		if (protectedLogEventRow == null) {
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_LOGROW);
			return null;
		}
		ProtectedLogToken protectedLogToken = getProtectedLogSession().getToken(protectedLogEventRow.getProtectionKeyIdentifier());
		if (protectedLogToken == null ) {
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_TOKEN);
		} else {
			try {
				if ( !protectedLogToken.verify(protectedLogEventRow.getAsByteArray(false), protectedLogEventRow.getProtection())) {
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
				} else {
					log.debug("<getValidLogEventRow");
					return protectedLogEventRow;
				}
			} catch (Exception e) {
				protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
				log.error("Internal logging error.", e);
			} 
		}
		return null;
	}
}
