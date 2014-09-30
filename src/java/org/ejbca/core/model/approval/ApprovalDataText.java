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
package org.ejbca.core.model.approval;

/**
 * Class used in presenting approval data for the approving administrator
 * Contains a header and a data part and booleans if they should be
 * translated or not.
 * 
 * @author Philip Vendil
 *
 * @version $Id$
 */
public class ApprovalDataText {
	String header;
	String data;
	boolean headerTranslateable;
	boolean dataTranslatable;
	
	public ApprovalDataText(String header, String data, boolean headerTranslateable, boolean dataTranslatable) {
		super();
		this.header = header;
		this.data = data;
		this.headerTranslateable = headerTranslateable;
		this.dataTranslatable = dataTranslatable;
	}
	
	public String getData() {
		return data;
	}

	public boolean isDataTranslatable() {
		return dataTranslatable;
	}

	public String getHeader() {
		return header;
	}

	public boolean isHeaderTranslateable() {
		return headerTranslateable;
	}
}
