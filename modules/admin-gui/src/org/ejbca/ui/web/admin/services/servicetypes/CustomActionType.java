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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Properties;

import org.ejbca.core.model.services.IAction;
import org.ejbca.ui.web.admin.CustomLoader;

/**
 * Class used to populate the fields in the customaction.jsp subview page. 
 * 
 *
 * @version $Id$
 */
public class CustomActionType extends ActionType {
	
	private static final long serialVersionUID = -1897582972418437359L;

    public static final String NAME = "CUSTOMACTION";
	
	public CustomActionType() {
		super("customaction.jsp", NAME, true);
	}

	private String autoClassPath;
    private String manualClassPath;
	
	private String propertyText;

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
        if (CustomLoader.isDisplayedInList(classPath, IAction.class)) {
            autoClassPath = classPath;
            manualClassPath = "";
        } else {
            autoClassPath = "";
            manualClassPath = classPath;
        }
    }

    public String getClassPath() {
        return autoClassPath != null && !autoClassPath.isEmpty() ? autoClassPath : manualClassPath;
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
	
	public boolean isCustom() {
		return true;
	}

}
