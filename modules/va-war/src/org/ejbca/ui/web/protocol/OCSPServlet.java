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

package org.ejbca.ui.web.protocol;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.protocol.certificatestore.CertificateCacheFactory;
import org.ejbca.core.protocol.certificatestore.ICertificateCache;
import org.ejbca.core.protocol.ocsp.OCSPData;

/** 
 * Servlet implementing server side of the Online Certificate Status Protocol (OCSP)
 * For a detailed description of OCSP refer to RFC2560.
 *
 * @author Thomas Meckel (Ophios GmbH), Tomas Gustavsson, Lars Silven
 * @version  $Id$
 */
public class OCSPServlet extends OCSPServletBase {

	private static final long serialVersionUID = 1L;

	@EJB
    private CAAdminSessionLocal caAdminSessionLocal;
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;

    public void init(ServletConfig config) throws ServletException {
    	super.init(config, new OCSPData(certificateStoreSession));
    }
    
    @Override
	protected OCSPCAServiceResponse extendedService(AuthenticationToken adm, int caid, OCSPCAServiceRequest request) throws CADoesntExistsException, ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, AuthorizationDeniedException {
        return (OCSPCAServiceResponse)this.caAdminSessionLocal.extendedService(adm, caid, request);
    }

    @Override
	protected ICertificateCache createCertificateCache() {
		return CertificateCacheFactory.getInstance(certificateStoreSession);
	}

    @Override
	protected void loadPrivateKeys(String password) {
        // not used by this servlet
    }
}
