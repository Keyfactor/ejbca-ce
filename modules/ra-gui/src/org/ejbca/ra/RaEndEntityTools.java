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
package org.ejbca.ra;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.faces.component.UIComponent;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaCertificateSearchResponse;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;

/**
 * Tools to handle common RA End Entity operations.
 * 
 * @version $Id$
 */
public class RaEndEntityTools {

    /**
     * Finds the certificates of an End Entity and sorts them by date issued (descending).
     * 
     * @param raMasterApiProxyBean the RaMasterApiProxyBeanLocal to be used in the search
     * @param authenticationToken the AuthenticationToken to be used in the search
     * @param username the username of the End Entity
     * @param raLocaleBean the RaLocaleBean to be used for the RaCertificateDetails objects
     * @return a list of RaCertificateDetails objects
     */
    public static List<RaCertificateDetails> searchCertsByUsernameSorted(
            final RaMasterApiProxyBeanLocal raMasterApiProxyBean, final AuthenticationToken authenticationToken,
            final String username, final RaLocaleBean raLocaleBean) {
        // Find certificates by username
        RaCertificateSearchResponse response = raMasterApiProxyBean.searchForCertificatesByUsername(authenticationToken, username);
        List<RaCertificateDetails> certificates = new ArrayList<>();
        RaCertificateDetails.Callbacks callbacks = new RaCertificateDetails.Callbacks() {
            @Override
            public RaLocaleBean getRaLocaleBean() {
                return raLocaleBean;
            }
            @Override
            public UIComponent getConfirmPasswordComponent() {
                return null;
            }
            @Override
            public boolean changeStatus(RaCertificateDetails raCertificateDetails, int newStatus, int newRevocationReason)
                    throws ApprovalException, WaitingForApprovalException {
                return false;
            }
            @Override
            public boolean recoverKey(RaCertificateDetails raCertificateDetails) throws ApprovalException, CADoesntExistsException,
                    AuthorizationDeniedException, WaitingForApprovalException,NoSuchEndEntityException, EndEntityProfileValidationException {
                return false;
            }
            @Override
            public boolean keyRecoveryPossible(RaCertificateDetails raCertificateDetails) {
                return false;
            }
        };
        for (CertificateDataWrapper cdw : response.getCdws()) {
            certificates.add(new RaCertificateDetails(cdw, callbacks, null, null, null));
        }
        // Sort by date created (descending)
        Collections.sort(certificates, new Comparator<RaCertificateDetails>() {
            @Override
            public int compare(RaCertificateDetails cert1, RaCertificateDetails cert2) {
                return cert1.getCreated().compareTo(cert2.getCreated()) * -1;
            }
        });
        return certificates;
    }
}
