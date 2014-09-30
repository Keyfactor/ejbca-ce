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
package org.ejbca.core.model.ca.caadmin.extendedcaservices;

import java.io.Serializable;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceTypes;

/**
 * 
 * @version $Id$
 *
 */
public class KeyRecoveryCAServiceInfo extends ExtendedCAServiceInfo implements Serializable {

	private static final long serialVersionUID = 2005286169126704029L;

    public KeyRecoveryCAServiceInfo(int status) {
		super(status);
	}

	@Override
	public String getImplClass() {
		return KeyRecoveryCAService.class.getName();
	}

	@Override
	public int getType() {
		return ExtendedCAServiceTypes.TYPE_KEYRECOVERYEXTENDEDSERVICE;
	}

}
