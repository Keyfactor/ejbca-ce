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

import java.io.IOException;
import java.util.Properties;

/**
 * Class used to populate the fields in the noaction subpage. 
 * 
 * @author Philip Vendil 2006 sep 30
 *
 * @version $Id: NoActionType.java,v 1.1 2006-10-14 05:01:44 herrvendil Exp $
 */
public class NoActionType extends ActionType {
	
	public static final String NAME = "NOACTION";
	
	
	public NoActionType() {
		super("noaction.jsp", NAME, true);
	}

    String unit;
    String value;


	public String getClassPath() {
		return "org.ejbca.core.model.services.actions.NoAction";
	}

	public Properties getProperties() throws IOException{
		Properties retval = new Properties();
		return retval;
	}
	
	public void setProperties(Properties properties) throws IOException{
	}

	public boolean isCustom() {
		return false;
	}


}
