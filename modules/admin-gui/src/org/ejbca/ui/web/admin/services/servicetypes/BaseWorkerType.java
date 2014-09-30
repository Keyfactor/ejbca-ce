/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Properties;

import org.ejbca.core.model.services.BaseWorker;
import org.ejbca.core.model.services.IWorker;

/**
 * Base type for workers
 * 
 * @version $Id$
 *
 */

public abstract class BaseWorkerType extends WorkerType {

    private static final long serialVersionUID = 7026884019102752494L;

    public static final String DEFAULT_TIMEUNIT = BaseWorker.UNIT_DAYS;
	public static final String DEFAULT_TIMEVALUE = "7";
	
	private List<String> selectedCANamesToCheck = new ArrayList<String>();
	private List<String> selectedCertificateProfilesToCheck = new ArrayList<String>();
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

	@Override
	public boolean isCustom() {		
		return false;
	}

	@Override
	public Collection<String> getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	@Override
	public Collection<String> getCompatibleIntervalTypeNames() {
		return compatibleIntervalTypeNames;
	}

	@Override
	public String getClassPath() {		
		return classpath;
	}

	@Override
	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {		
	    Properties retval = new Properties(); 
        String caIdString = null;
        for(String cAid  : getSelectedCANamesToCheck()) { 
            if(!cAid.trim().equals("")){
              if(caIdString == null) {
                caIdString = cAid;
              }else{
                caIdString += ";"+cAid;
              }
            }
        }
        if (caIdString != null) {           
            retval.setProperty(IWorker.PROP_CAIDSTOCHECK, caIdString);
        }
        String certificateProfileIdString = null;
        for(String certificateProfileId : getSelectedCertificateProfilesToCheck()) {
            if(!certificateProfileId.trim().equals("")){
                  if(certificateProfileIdString == null) {
                      certificateProfileIdString = certificateProfileId;
                  }else{
                      certificateProfileIdString += ";"+certificateProfileId;
                  }
                }
        }
        if (certificateProfileIdString != null) {         
            retval.setProperty(IWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK, certificateProfileIdString);
        }
        return retval;
	}

	@Override
    public void setProperties(Properties properties) throws IOException {
        ArrayList<String> selectedCANamesToCheck = new ArrayList<String>();
        selectedCANamesToCheck.addAll(Arrays.asList(properties.getProperty(IWorker.PROP_CAIDSTOCHECK, "").split(";")));
        setSelectedCANamesToCheck(selectedCANamesToCheck);
        ArrayList<String> selectedCertificateProfileNamesToCheck = new ArrayList<String>();
        selectedCertificateProfileNamesToCheck.addAll(Arrays.asList(properties.getProperty(IWorker.PROP_CERTIFICATE_PROFILE_IDS_TO_CHECK, "")
                .split(";")));
        setSelectedCertificateProfilesToCheck(selectedCertificateProfileNamesToCheck);      
    }
    
    /**
     * @return the selectedCertificateProfilesToCheck
     */
    public List<String> getSelectedCertificateProfilesToCheck() {
        return selectedCertificateProfilesToCheck;
    }

    /**
     * @param selectedCertificateProfilesToCheck the selectedCertificateProfilesToCheck to set
     */
    public void setSelectedCertificateProfilesToCheck(List<String> selectedCertificateProfilesToCheck) {
        this.selectedCertificateProfilesToCheck = selectedCertificateProfilesToCheck;
    }

}
