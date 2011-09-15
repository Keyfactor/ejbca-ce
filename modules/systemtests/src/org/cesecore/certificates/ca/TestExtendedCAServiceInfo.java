/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/ 
package org.cesecore.certificates.ca;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;

/**
 * @version $Id$
 */ 
public class TestExtendedCAServiceInfo extends ExtendedCAServiceInfo {

	private static final long serialVersionUID = 1L;

	public static final int type = 4712;
	
	public TestExtendedCAServiceInfo(int status) {
		super(status);
	}

	@Override
	public String getImplClass() {
		return TestExtendedCAService.class.getName();
	}

	@Override
	public int getType() {
		return TestExtendedCAServiceInfo.type;
	}

}
