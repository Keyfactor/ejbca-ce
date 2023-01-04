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

import java.io.Serializable;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.component.UIComponent;
import javax.faces.context.FacesContext;
import javax.faces.view.ViewScoped;
import javax.inject.Inject;
import javax.inject.Named;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ra.RaCertificateDetails.Callbacks;

/**
 * Backing bean for certificate details view.
 *  
 * @version $Id$
 */
@Named
@ViewScoped
public class RaViewCertBean implements Serializable {

    private static final long serialVersionUID = 1L;

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @Inject
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @Inject
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private String fingerprint = null;
    private RaCertificateDetails raCertificateDetails = null;
    private Map<Integer, String> eepIdToNameMap = null;
    private Map<Integer, String> cpIdToNameMap = null;
    private Map<String,String> caSubjectToNameMap = new HashMap<>();
    private Map<String, Boolean> caNameToAllowsChangeOfRevocationReason = new HashMap<>();
    private Map<String, Boolean> cpNameToAllowsRevocationBackdating = new HashMap<>();

    private final Callbacks raCertificateDetailsCallbacks = new RaCertificateDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
            return raLocaleBean;
        }
        @Override
        public UIComponent getConfirmPasswordComponent() {
            return null;
        }
        @Override
        public boolean changeStatus(RaCertificateDetails raCertificateDetails, int newStatus, int newRevocationReason) throws ApprovalException, WaitingForApprovalException {
            final boolean ret = raMasterApiProxyBean.changeCertificateStatus(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getFingerprint(),
                    newStatus, newRevocationReason);
            if (ret) {
                // Re-initialize object if status has changed
                final CertificateDataWrapper cdw = raMasterApiProxyBean.searchForCertificate(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getFingerprint());
                raCertificateDetails.reInitialize(cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap,
                        caNameToAllowsChangeOfRevocationReason, cpNameToAllowsRevocationBackdating);
            }
            return ret;
        }
        @Override
        public void changeRevocationReason(final RaCertificateDetails raCertificateDetails, final int newRevocationReason,
                final Date newDate, final String issuerDn)
                throws NoSuchEndEntityException, ApprovalException, RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException,
                CADoesntExistsException, AuthorizationDeniedException, WaitingForApprovalException {
            raMasterApiProxyBean.revokeCert(
                    raAuthenticationBean.getAuthenticationToken(), new BigInteger(raCertificateDetails.getSerialnumberRaw()), newDate,
                    issuerDn, newRevocationReason, true);
            final CertificateDataWrapper cdw = raMasterApiProxyBean.searchForCertificate(raAuthenticationBean.getAuthenticationToken(),
                    raCertificateDetails.getFingerprint());
            raCertificateDetails.reInitialize(cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap,
                    caNameToAllowsChangeOfRevocationReason, cpNameToAllowsRevocationBackdating);
        }
        @Override
        public boolean recoverKey(RaCertificateDetails raCertificateDetails) throws ApprovalException, CADoesntExistsException, AuthorizationDeniedException, WaitingForApprovalException, 
                                    NoSuchEndEntityException, EndEntityProfileValidationException {
            final boolean ret = raMasterApiProxyBean.markForRecovery(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getUsername(), raCertificateDetails.getPassword(), 
                                    EJBTools.wrap(raCertificateDetails.getCertificate()), false);
            return ret;
        }
        @Override
        public boolean keyRecoveryPossible(RaCertificateDetails raCertificateDetails) {
            final boolean ret = raMasterApiProxyBean.keyRecoveryPossible(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getCertificate(), raCertificateDetails.getUsername());
            return ret;
        }
    };

    @PostConstruct
    public void postConstruct() {
        fingerprint = ((HttpServletRequest) FacesContext.getCurrentInstance().getExternalContext().getRequest()).getParameter("fp");
        if (fingerprint!=null) {
            final CertificateDataWrapper cdw = raMasterApiProxyBean.searchForCertificate(raAuthenticationBean.getAuthenticationToken(), fingerprint);
            if (cdw!=null) {
                cpIdToNameMap = raMasterApiProxyBean.getAuthorizedCertificateProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
                eepIdToNameMap = raMasterApiProxyBean.getAuthorizedEndEntityProfileIdsToNameMap(raAuthenticationBean.getAuthenticationToken());
                final List<CAInfo> caInfos = new ArrayList<>(raMasterApiProxyBean.getAuthorizedCas(raAuthenticationBean.getAuthenticationToken()));
                final IdNameHashMap<CertificateProfile> cpMap = raMasterApiProxyBean.getAllAuthorizedCertificateProfiles(
                        raAuthenticationBean.getAuthenticationToken()); 
                for (Integer cpId : cpMap.idKeySet()) {
                    final CertificateProfile currentCp = cpMap.getValue(cpId);
                    cpNameToAllowsRevocationBackdating.put(cpIdToNameMap.get(cpId), currentCp.getAllowBackdatedRevocation());
                }
                for (final CAInfo caInfo : caInfos) {
                    caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
                    caNameToAllowsChangeOfRevocationReason.put(caInfo.getName(), caInfo.isAllowChangingRevocationReason());
                }
                raCertificateDetails = new RaCertificateDetails(cdw, raCertificateDetailsCallbacks,
                        cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap, caNameToAllowsChangeOfRevocationReason,
                        cpNameToAllowsRevocationBackdating);
            }
        }
    }

    public String getFingerprint() { return fingerprint; }
    public RaCertificateDetails getCertificate() { return raCertificateDetails; }
}
