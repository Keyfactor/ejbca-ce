/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.core.model.log;

import java.util.Date;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.ejb.log.ProtectedLogSession;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Thread-safe singleton that invokes forwards a request from the verification service.
 * @version $Id$  
 * @deprecated
 */
public class ProtectedLogVerifier {

	private ProtectedLogSession protectedLogSession = null;

	private static final Logger log = Logger.getLogger(ProtectedLogVerifier.class);
    private static final InternalResources intres = InternalResources.getInstance();
	
	private static ProtectedLogVerifier instance = null;
	
	private long timeOfLastExecution = 0;
	private long lastKnownEventTime = 0;
	private boolean isRunning = false;
	private boolean isCanceled = false;
	private boolean isCanceledPermanently = false;
	long freezeThreshold = ProtectedLogConfiguration.getVerifyFreezeThreshold();
	long lastSuccessfulVerification = 0;

	private ProtectedLogActions protectedLogActions = null;
	
	private ProtectedLogVerifier() {
		protectedLogActions = new ProtectedLogActions(ProtectedLogConstants.ACTION_ALL);
	}
	
	/**
	 * Does not support update properties yet.
	 * @return
	 */
	public static ProtectedLogVerifier instance() {
		if (instance == null) {
			instance = new ProtectedLogVerifier();
		}
		return instance;
	}
	
	private ProtectedLogSession getProtectedLogSession() {
		try {
			if (protectedLogSession == null) {
				//protectedLogSession = ((IProtectedLogSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IProtectedLogSessionLocalHome.COMP_NAME)).create();
				protectedLogSession = new EjbLocalHelper().getProtectedLogSession();
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
		if (getBusy()) {
			run();
		}
	}
	
	synchronized boolean getBusy() {
		if (isCanceledPermanently || isRunning) {
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
		isCanceled = isRunning;
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
		log.trace(">run");
		long startTimeOfExecution = new Date().getTime();
		try  {
			ProtectedLogEventIdentifier protectedLogEventIdentifier = null;
			// Verify that the log hasn't been emptied since last run
			// Verify that the log hasn't been rolled back since last run
			protectedLogEventIdentifier = verifyLastEvent();
			if (protectedLogEventIdentifier != null) {
		    	log.error(intres.getLocalizedMessage("protectedlog.verifier.failed", protectedLogEventIdentifier.getNodeGUID(),
		    			protectedLogEventIdentifier.getCounter()));
			} else {
				// Verify entire log
				// Verify that log hasn't been frozen for any node
				// Verify that each protect operation had a valid certificate and is not about to expire without a valid replacement
				try {
					protectedLogEventIdentifier = getProtectedLogSession().verifyEntireLog(ProtectedLogConstants.ACTION_ALL, freezeThreshold);	//verifyEntireLog();
					if (protectedLogEventIdentifier != null) {
				    	log.error(intres.getLocalizedMessage("protectedlog.verifier.failed", protectedLogEventIdentifier.getNodeGUID(),
				    			protectedLogEventIdentifier.getCounter()));
					} else {
						lastSuccessfulVerification = startTimeOfExecution;
					}
				} catch (Exception e) {
			    	log.error(intres.getLocalizedMessage("protectedlog.error.internallogerror", protectedLogEventIdentifier.getNodeGUID(),
			    			protectedLogEventIdentifier.getCounter()));
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
				}
			}
		} finally {
			timeOfLastExecution = startTimeOfExecution;
			isRunning = false;
			isCanceled = false;
		}
		log.trace("<run");
	}
	
	public long getTimeOfLastExecution() {
		return timeOfLastExecution;
	}
	
	/**
	 * Verify that the log hasn't been emptied since last run
	 * Verify that the log hasn't been rolled back since last run
	 */
	private ProtectedLogEventIdentifier verifyLastEvent() {
		log.trace(">verifyLastEvent");
		ProtectedLogActions protectedLogActions = new ProtectedLogActions(ProtectedLogConstants.ACTION_ALL); 
		ProtectedLogEventIdentifier protectedLogEventIdentifier = getProtectedLogSession().findNewestProtectedLogEventRow();
		// Is log empy?
		if (protectedLogEventIdentifier == null) {
	    	log.error(intres.getLocalizedMessage("protectedlog.error.emptyorunprotected"));
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_EMPTY_LOG);
			return protectedLogEventIdentifier;
		} else {
			// Has log been rolled back
			ProtectedLogEventRow protectedLogEventRow = getValidLogEventRow(protectedLogEventIdentifier);
			if (protectedLogEventRow != null) {
				// Compare time with last known event-time
				long currentEventTime = protectedLogEventRow.getEventTime();
				if (lastKnownEventTime > currentEventTime) {
			    	log.error(intres.getLocalizedMessage("protectedlog.error.rolledback"));
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_ROLLED_BACK);
					return protectedLogEventIdentifier;
				}
				lastKnownEventTime = currentEventTime;
			}
		}
		log.trace("<verifyLastEvent");
		return null;
	}

	/**
	 * Retrieves and verifies the requested ProtectedLogEvent or null if not found.
	 */
	private ProtectedLogEventRow getValidLogEventRow(ProtectedLogEventIdentifier protectedLogEventIdentifier) {
		log.trace(">getValidLogEventRow");
		ProtectedLogEventRow protectedLogEventRow = getProtectedLogSession().getProtectedLogEventRow(protectedLogEventIdentifier);
		if (protectedLogEventRow == null) {
			// We take no action here. We want to return null to show the caller that the event was not found.
			return null;
		}
		IProtectedLogToken protectedLogToken = getProtectedLogSession().getToken(protectedLogEventRow.getProtectionKeyIdentifier());
		if (protectedLogToken == null ) {
	    	log.error(intres.getLocalizedMessage("protectedlog.error.tokenmissing"));
			protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MISSING_TOKEN);
		} else {
			try {
				if ( !protectedLogToken.verify(protectedLogEventRow.getAsByteArray(false), protectedLogEventRow.getProtection())) {
			    	log.error(intres.getLocalizedMessage("protectedlog.error.logrowmissing"));
					protectedLogActions.takeActions(IProtectedLogAction.CAUSE_MODIFIED_LOGROW);
				} else {
					log.trace("<getValidLogEventRow");
					return protectedLogEventRow;
				}
			} catch (Exception e) {
		    	log.error(intres.getLocalizedMessage("protectedlog.error.internallogerror"), e);
				protectedLogActions.takeActions(IProtectedLogAction.CAUSE_INTERNAL_ERROR);
			} 
		}
		return null;
	}
}
