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
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Properties;

/**
 * Abstract base class of all type of service components. Used to manages
 * available and compatible JSF SubViews
 * 
 *
 * @version $Id$
 */
public abstract class ServiceType implements Serializable{
	
	private static final long serialVersionUID = -1788904631086719809L;
    private String jSFSubViewPage;
	private String name;
	private boolean translatable;


	/**
	 * 
	 * @param subViewPage the name of the subViewPage to link in the page
	 * @param name, the name of the page when it is selected in the GUI
	 * @param translatable if the name should be looked up in the resource files or not. 
	 */
	public ServiceType(String subViewPage, String name, boolean translatable) {
		super();
		jSFSubViewPage = subViewPage;
		this.name = name;
		this.translatable = translatable;
	}

	/**
	 * @return the name of the subViewPage to link in the page
	 */
	public String getJSFSubViewPage() {
		return jSFSubViewPage;
	}

	/**
	 * @return the name of the page when it is selected in the GUI
	 */
	public String getName() {
		return name;
	}

	/**
	 * @return if the name should be looked up in the resource files or not. 
	 */
	public boolean isTranslatable() {
		return translatable;
	}
	
	/**
	 * All implementing classes should populate the properties
	 * @return
	 */
	public abstract Properties getProperties(ArrayList<String> errorMessages) throws IOException;
	
	/**
	 * All implementing classes should populate the gui data
	 * @return
	 */
	public abstract void setProperties(Properties properties) throws IOException;
	
	/**
	 * The classPath of the component in the model
	 */
    public abstract String getClassPath();
    
    /**
     * Return true if this type is a custom type 
     */
    public abstract boolean isCustom();
}
