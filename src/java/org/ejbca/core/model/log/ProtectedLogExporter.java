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

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.config.ProtectedLogConfiguration;
import org.ejbca.core.ejb.log.ProtectedLogSession;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.util.CertTools;

/**
 * Thread-safe singleton that invokes forwards an export from the export service.
 * @version $Id$
 * @deprecated
 */
public class ProtectedLogExporter {
	
	private static final Logger log = Logger.getLogger(ProtectedLogExporter.class);

	private static ProtectedLogExporter instance = null;

	private ProtectedLogSession protectedLogSession = null;

	private boolean isRunning = false;
	private boolean isCanceled = false;
	private boolean isCanceledPermanently = false;

	private boolean deleteAfterExport = ProtectedLogConfiguration.getExportDeleteAfterExport();
	private long atLeastThisOld = ProtectedLogConfiguration.getExportOlderThan();
	
	private String currentHashAlgorithm = ProtectedLogConfiguration.getExportHashAlgorithm(); 

	private ProtectedLogExporter() {
		CertTools.installBCProvider();
	}

	public static ProtectedLogExporter instance() {
		if (instance == null) {
			instance = new ProtectedLogExporter();
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

	public void runIfNotBusy() {
		if (!isCanceledPermanently && getBusy()) {
			run();
		}
	}
	
	public boolean isRunning() {
		return isRunning;
	}

	private synchronized boolean getBusy() {
		if (isRunning) {
			return false;
		}
		return (isRunning = true);
	}
	
	/**
	 * Inform the service next time it ask, that it is requested to stop.
	 */
	public void cancelExport() {
		isCanceled = isRunning;
	}
	
	/**
	 * Inform the service next time it ask, that it is requested to stop and don't start it again.
	 */
	public void cancelExportsPermanently() {
		isCanceledPermanently = true;
	}
	
	public boolean isCanceled() {
		return isCanceled || isCanceledPermanently;
	}
	
	// Exports chunk of log
	synchronized private void run() {
		log.trace(">run");
		IProtectedLogExportHandler protectedLogExportHandler = null;
		try {
			Class implClass = Class.forName(ProtectedLogConfiguration.getExportHandlerClassName());
			protectedLogExportHandler = (IProtectedLogExportHandler) implClass.newInstance();
			getProtectedLogSession().exportLog(protectedLogExportHandler, ProtectedLogConstants.ACTION_ALL, currentHashAlgorithm, deleteAfterExport, atLeastThisOld);
		} catch (Exception e) {
			log.error(e);
		} finally {
			isRunning = false;
			isCanceled = false;
		}
		log.trace("<run");
	}
}
