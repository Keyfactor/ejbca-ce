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
import java.util.Properties;

/**
 * Class used to populate the fields in the customaction.jsp subview page. 
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: CustomActionType.java 5585 2008-05-01 20:55:00Z anatom $
 */
public class CustomActionType extends ActionType {
	
	public static final String NAME = "CUSTOMACTION";
	
	public CustomActionType() {
		super("customaction.jsp", NAME, true);
	}

	private String classPath;
	
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
	 * @param classPath the classPath to set
	 */
	public void setClassPath(String classPath) {
		this.classPath = classPath;
	}

	public String getClassPath() {
		return classPath;
	}

	public Properties getProperties(ArrayList errorMessages) throws IOException{
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
