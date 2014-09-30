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
import java.util.Properties;

/**
 * Class used to populate the fields in the noaction subpage. 
 * 
 *
 * @version $Id$
 */
public class NoActionType extends ActionType {
	
	private static final long serialVersionUID = -5063026816886312970L;

    public static final String NAME = "NOACTION";
	
	private transient Properties properties = new Properties();
	
	public NoActionType() {
		super("noaction.jsp", NAME, true);
	}

    String unit;
    String value;


	public String getClassPath() {
		return org.ejbca.core.model.services.actions.NoAction.class.getName();
	}

	public Properties getProperties(ArrayList<String> errorMessages) throws IOException {		
		return properties;
	}
	
	public void setProperties(Properties properties) throws IOException {
		this.properties = properties;
	}

	public boolean isCustom() {
		return false;
	}


}
