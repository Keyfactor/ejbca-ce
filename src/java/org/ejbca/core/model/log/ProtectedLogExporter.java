package org.ejbca.core.model.log;

import java.util.Properties;

import javax.ejb.EJBException;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.log.IProtectedLogSessionLocal;
import org.ejbca.core.ejb.log.IProtectedLogSessionLocalHome;
import org.ejbca.util.CertTools;

/**
 * Thread-safe singleton that invokes fowards an export from the export service.  
 */
public class ProtectedLogExporter {
	
	public static final String CONF_HASH_ALGO						= "exportservice.hashAlgorithm";
	public static final String CONF_DELETE_AFTER_EXPORT	= "exportservice.deleteafterexport";
	public static final String CONF_EXPORT_OLDER_THAN		= "exportservice.exportolderthan";

	private static final Logger log = Logger.getLogger(ProtectedLogExporter.class);

	private static ProtectedLogExporter instance = null;

	private IProtectedLogSessionLocal protectedLogSession = null;

	private Properties properties = null;
	private boolean isRunning = false;

	private ProtectedLogActions protectedLogActions = null;
	private boolean deleteAfterExport = false;
	private long atLeastThisOld = 0;
	
	private String currentHashAlgorithm = null; 

	protected ProtectedLogExporter(Properties properties) {
		this.properties = properties;
		CertTools.installBCProvider();
		currentHashAlgorithm = properties.getProperty(CONF_HASH_ALGO, "SHA-256");
		protectedLogActions = new ProtectedLogActions(properties);
		deleteAfterExport = properties.getProperty(CONF_DELETE_AFTER_EXPORT, "false").equalsIgnoreCase("true");
		atLeastThisOld = Long.parseLong(properties.getProperty(CONF_EXPORT_OLDER_THAN, "0")) * 60 * 1000;
	}

	public static ProtectedLogExporter instance(Properties properties) {
		if (instance == null) {
			instance = new ProtectedLogExporter(properties);
		}
		return instance;
	}

	/**
	 * @return null if no instance exists
	 */
	public static ProtectedLogExporter instance() {
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

	public void runIfNotBusy() {
		if (getBusy()) {
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
	
	// Exports chunk of log
	synchronized private void run() {
		IProtectedLogExportHandler protectedLogExportHandler = null;
		try {
			Class implClass = Class.forName(properties.getProperty("exportservice.exporthandler", ProtectedLogDummyExportHandler.class.getName()).trim());
			protectedLogExportHandler =(IProtectedLogExportHandler) implClass.newInstance();
			getProtectedLogSession().exportLog(protectedLogExportHandler, properties, protectedLogActions, currentHashAlgorithm, deleteAfterExport, atLeastThisOld);
		} catch (Exception e) {
			log.error(e);
		}
		isRunning = false;
	}
}
