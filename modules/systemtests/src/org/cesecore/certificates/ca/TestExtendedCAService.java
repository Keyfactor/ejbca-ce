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

import java.util.HashMap;

import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.keys.token.CryptoToken;

/**
 * @version $Id$
 */ 
public class TestExtendedCAService extends ExtendedCAService {

	public TestExtendedCAService(ExtendedCAServiceInfo info) {
		super(info);
		data.put(ExtendedCAServiceInfo.IMPLEMENTATIONCLASS, this.getClass().getName());
		setStatus(info.getStatus());
	}

    public TestExtendedCAService(HashMap<?, ?> data) {
    	super(data);
    	loadData(data);
    }

	private static final long serialVersionUID = 1L;
	
	public static int didrun = 0;
	
	@Override
	public ExtendedCAServiceResponse extendedService(CryptoToken cryptoToken,
			ExtendedCAServiceRequest request)
	throws ExtendedCAServiceRequestException,
	IllegalExtendedCAServiceRequestException,
	ExtendedCAServiceNotActiveException {
		didrun++;
		return new TestExtendedCAServiceResponse();
	}

	@Override
	public ExtendedCAServiceInfo getExtendedCAServiceInfo() {
		return new TestExtendedCAServiceInfo(getStatus());
	}

	@Override
	public void init(CryptoToken cryptoToken,CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception {
		final ExtendedCAServiceInfo info = (ExtendedCAServiceInfo) getExtendedCAServiceInfo();
		setStatus(info.getStatus());
	}

	@Override
	public void update(CryptoToken cryptoToken, ExtendedCAServiceInfo info, CA ca, final AvailableCustomCertificateExtensionsConfiguration cceConfig) {
		setStatus(info.getStatus());
	}

	@Override
	public float getLatestVersion() {
		return 0;
	}

	@Override
	public void upgrade() {
	}

}
