package org.ejbca.core.model.log;

import java.io.Serializable;
import java.util.Properties;

import org.apache.log4j.Logger;

/**
 * Dummy implentation. This is the simplest possible (and most useless) implementation.
 */
public class ProtectedLogDummyExportHandler implements IProtectedLogExportHandler, Serializable {

	private static final Logger log = Logger.getLogger(ProtectedLogDummyExportHandler.class);

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public void init(Properties properties, long exportEndTime, long exportStartTime, boolean forced) {
		log.info("Export initialized for interval " + exportStartTime + " - " + exportEndTime + ".");
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public boolean done(String currentHashAlgorithm, byte[] exportedHash, byte[] lastExportedHash) {
		log.info("Export to console finished..");
		return true;
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public boolean update(int adminType, String admindata, int caid, int module, long eventTime, String username, String certificateSerialNumber, String certificateIssuerDN, int eventId, String eventComment) {
		log.info("Export update to console: "+eventTime + " " + eventComment);
		return true;
	}

	/**
	 * @see org.ejbca.core.model.log.IProtectedLogExportHandler
	 */
	public void abort() {
		log.info("Export aborted.");
	}
}
