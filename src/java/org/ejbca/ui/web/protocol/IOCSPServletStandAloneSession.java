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

import org.ejbca.core.ejb.ca.store.LocalCertificateStoreOnlyDataSessionBean;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceNotActiveException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.IllegalExtendedCAServiceRequestException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.OCSPCAServiceResponse;
import org.ejbca.core.model.log.Admin;

/**
 * @author lars
 * @versioon $Id$
 *
 */
public interface IOCSPServletStandAloneSession {
    /**
     * @param caid
     * @param request
     * @return
     * @throws ExtendedCAServiceRequestException
     * @throws ExtendedCAServiceNotActiveException
     * @throws IllegalExtendedCAServiceRequestException
     */
    OCSPCAServiceResponse extendedService(int caid, OCSPCAServiceRequest request) throws ExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException, IllegalExtendedCAServiceRequestException;
    /**
     * @param bean . The calling object
     * @return  The string to be placed in the servlet response
     */
    String healthCheck(LocalCertificateStoreOnlyDataSessionBean bean);
    /**
     * @param adm
     * @param bean . The calling object
     * @throws Exception
     */
    void loadPrivateKeys(Admin adm, LocalCertificateStoreOnlyDataSessionBean bean) throws Exception;
    /**
     * @return Tells if the servlet is usable.
     */
    boolean isActive();
}
