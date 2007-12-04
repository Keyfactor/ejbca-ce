package org.ejbca.core.model.services.workers;

import org.apache.log4j.Logger;
import org.ejbca.core.model.log.ProtectedLogExporter;
import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.ServiceExecutionFailedException;


public class ProtectedLogExportWorker extends BaseWorker {

	private static final Logger log = Logger.getLogger(ProtectedLogExportWorker.class);
	
	public static final String DEFAULT_SERVICE_NAME = "__ProtectedLogExportService__";
	public static final String CONF_EXPORT_INTERVAL = "exportservice.invokationinterval";
	public static final String DEFAULT_EXPORT_INTERVAL = "1440";

	public void work() throws ServiceExecutionFailedException {
		log.debug(">ProtectedLogExportWorker.work");
		ProtectedLogExporter protectedLogExporter = ProtectedLogExporter.instance(properties);
		protectedLogExporter.runIfNotBusy();
		log.debug("<ProtectedLogExportWorker done");
	}

}
