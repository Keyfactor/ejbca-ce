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
package org.ejbca.ui.web.admin.services.servicetypes;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import org.ejbca.core.model.services.IWorker;
import org.ejbca.ui.web.admin.CustomLoader;
import org.ejbca.ui.web.admin.services.ServiceConfigurationView;

/**
 * Class used to populate the fields in the customworker.jsp subview page. 
 * 
 * Is comatible with custom action and custom interval. 
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id$
 */
public class CustomWorkerType extends WorkerType {
	
	private static final long serialVersionUID = 1790314768357040269L;
    public static final String NAME = "CUSTOMWORKER";
	
    private String autoClassPath;
    private String manualClassPath;
    private String propertyText;
    private Collection<String> compatibleActionTypeNames = new ArrayList<String>();
    private Collection<String> compatibleIntervalTypeNames = new ArrayList<String>();
    
	public CustomWorkerType() {
		super("customworker.jsp", NAME, true);
		
		compatibleActionTypeNames.add(CustomActionType.NAME);
		compatibleActionTypeNames.add(NoActionType.NAME);
		compatibleActionTypeNames.add(MailActionType.NAME);
		
		compatibleIntervalTypeNames.add(CustomIntervalType.NAME);
		compatibleIntervalTypeNames.add(PeriodicalIntervalType.NAME);
	}

	/**
	 * @return the propertyText
	 */
	public String getPropertyText() {
		return propertyText;
	}

	/**
	 * @param propertyText the propertyText to set
	 */
	public void setPropertyText(String propertyText) {
		this.propertyText = propertyText;
	}

	/**
	 * Sets the class path, and detects if it is an auto-detected class
	 * or a manually specified class.
	 */
	public void setClassPath(String classPath) {
	    if (CustomLoader.isAutoClass(classPath, IWorker.class)) {
            autoClassPath = classPath;
            manualClassPath = "";
	    } else {
            autoClassPath = "";
            manualClassPath = classPath;
	    }
	}

	public String getClassPath() {
		return !autoClassPath.isEmpty() ? autoClassPath : manualClassPath;
	}
	
	public void setAutoClassPath(String classPath) {
        autoClassPath = classPath;
    }

    public String getAutoClassPath() {
        return autoClassPath;
    }
    
    public void setManualClassPath(String classPath) {
        manualClassPath = classPath;
    }

    public String getManualClassPath() {
        return manualClassPath;
    }

	public Properties getProperties(ArrayList<String> errorMessages) throws IOException{
		Properties retval = new Properties();
	    retval.load(new ByteArrayInputStream(getPropertyText().getBytes()));		
		return retval;
	}
	
	public void setProperties(Properties properties) throws IOException{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();		
		properties.store(baos, null);		
		setPropertyText(new String(baos.toByteArray()));
	}
	
	/**
	 * @return the names of the Compatible Action Types
	 */
	public Collection<String> getCompatibleActionTypeNames() {
		return compatibleActionTypeNames;
	}

	/**
	 * @return the names of the Compatible Interval Types
	 */
	public Collection<String> getCompatibleIntervalTypeNames() {
		return compatibleIntervalTypeNames;
	}
	
	public boolean isCustom() {
		return true;
	}

}
