package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Properties;

import org.ejbca.core.model.services.BaseWorker;

public abstract class BaseWorkerType extends WorkerType {

    private static final long serialVersionUID = 7026884019102752494L;

    public static final String DEFAULT_TIMEUNIT = BaseWorker.UNIT_DAYS;
	public static final String DEFAULT_TIMEVALUE = "7";
	
	private List<String> selectedCANamesToCheck = new ArrayList<String>();
	private Collection<String> compatibleActionTypeNames = new ArrayList<String>();
	private Collection<String> compatibleIntervalTypeNames = new ArrayList<String>();
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
		compatibleActionTypeNames = new ArrayList<String>();
	}
	protected void addCompatibleIntervalTypeName(String name) {
		compatibleIntervalTypeNames.add(name);
	}
	protected void deleteAllCompatibleIntervalTypes() {
		compatibleIntervalTypeNames = new ArrayList<String>();
	}
	public List<String> getSelectedCANamesToCheck() {
		return selectedCANamesToCheck;
	}
	public void setSelectedCANamesToCheck(List<String> selectedCANamesToCheck) {
		this.selectedCANamesToCheck = selectedCANamesToCheck;
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
	public Collection<String> getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.WorkerType#getCompatibleIntervalTypeNames()
	 */
	public Collection<String> getCompatibleIntervalTypeNames() {
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
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {		
		Properties retval = new Properties();

		Iterator<String> iter = getSelectedCANamesToCheck().iterator();		
		String caIdString = null;
		while(iter.hasNext()){
			String cAid = (String) iter.next();
			if(!cAid.trim().equals("")){
			  if(caIdString == null) {
				caIdString = cAid;
			  }else{
				caIdString += ";"+cAid;
			  }
			}
		}
		if (caIdString != null) {			
			retval.setProperty(BaseWorker.PROP_CAIDSTOCHECK, caIdString);
		}
		return retval;
	}

	/**
	 * @see org.ejbca.ui.web.admin.services.servicetypes.ServiceType#setProperties(java.util.Properties)
	 */
	public void setProperties(Properties properties) throws IOException {
		ArrayList<String> selectedCANamesToCheck = new ArrayList<String>();
		String[] caIdsToCheck = properties.getProperty(BaseWorker.PROP_CAIDSTOCHECK,"").split(";");
		for(int i=0;i<caIdsToCheck.length;i++){
			selectedCANamesToCheck.add(caIdsToCheck[i]);
		}
		setSelectedCANamesToCheck(selectedCANamesToCheck);			
	}

}