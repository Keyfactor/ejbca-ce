package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import org.ejbca.core.model.services.BaseWorker;

public abstract class BaseWorkerType extends WorkerType {

	public static final String DEFAULT_TIMEUNIT = BaseWorker.UNIT_DAYS;
	public static final String DEFAULT_TIMEVALUE = "7";
	
	private transient Properties properties = new Properties();
	private Collection compatibleActionTypeNames = new ArrayList();
	private Collection compatibleIntervalTypeNames = new ArrayList();
	private String classpath = null;

	public BaseWorkerType(String subViewPage, String name, boolean translatable, String classpath) {
		super(subViewPage, name, translatable);
		this.classpath = classpath;
	}

	//
	// Helper methods for BaseWorkerType to be used by extending classes
	//
	protected void addCompatibleActionTypeName(String name) {
		compatibleActionTypeNames.add(name);
	}
	protected void deleteAllCompatibleActionTypes() {
		compatibleActionTypeNames = new ArrayList();
	}
	protected void addCompatibleIntervalTypeName(String name) {
		compatibleIntervalTypeNames.add(name);
	}
	protected void deleteAllCompatibleIntervalTypes() {
		compatibleIntervalTypeNames = new ArrayList();
	}
	//
	// Methods implementing WorkerType
	// 
	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#isCustom()
	 */
	public boolean isCustom() {		
		return false;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleActionTypeNames()
	 */
	public Collection getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleIntervalTypeNames()
	 */
	public Collection getCompatibleIntervalTypeNames() {
		return compatibleIntervalTypeNames;
	}

	/**
	 * 
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getClassPath()
	 */
	public String getClassPath() {		
		return classpath;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#getProperties()
	 */
	public Properties getProperties(ArrayList errorMessages) throws IOException {		
		return properties;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	public void setProperties(Properties properties) throws IOException {
		this.properties = properties;
	}

}