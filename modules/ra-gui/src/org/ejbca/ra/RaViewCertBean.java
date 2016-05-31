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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;
import javax.servlet.http.HttpServletRequest;

import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.ra.RaCertificateDetails.Callbacks;

/**
 * Backing bean for certificate details view.
 *  
 * @version $Id$
 */
@ManagedBean
@ViewScoped
public class RaViewCertBean implements Serializable {

    private static final long serialVersionUID = 1L;

    @EJB
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(final RaAuthenticationBean raAuthenticationBean) { this.raAuthenticationBean = raAuthenticationBean; }

    @ManagedProperty(value="#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) { this.raLocaleBean = raLocaleBean; }

    private String fingerprint = null;
    private RaCertificateDetails raCertificateDetails = null;
    private Map<Integer, String> eepIdToNameMap = null;
    private Map<Integer, String> cpIdToNameMap = null;
    private Map<String,String> caSubjectToNameMap = new HashMap<>();

    private final Callbacks raCertificateDetailsCallbacks = new RaCertificateDetails.Callbacks() {
        @Override
        public RaLocaleBean getRaLocaleBean() {
            return raLocaleBean;
        }
        @Override
        public boolean changeStatus(RaCertificateDetails raCertificateDetails, int newStatus, int newRevocationReason) throws ApprovalException, WaitingForApprovalException {
            final boolean ret = raMasterApiProxyBean.changeCertificateStatus(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getFingerprint(),
                    newStatus, newRevocationReason);
            if (ret) {
                // Re-initialize object if status has changed
                final CertificateDataWrapper cdw = raMasterApiProxyBean.searchForCertificate(raAuthenticationBean.getAuthenticationToken(), raCertificateDetails.getFingerprint());
                raCertificateDetails.reInitialize(cdw, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
            }
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
                for (final CAInfo caInfo : caInfos) {
                    caSubjectToNameMap.put(caInfo.getSubjectDN(), caInfo.getName());
                }
                raCertificateDetails = new RaCertificateDetails(cdw, raCertificateDetailsCallbacks, cpIdToNameMap, eepIdToNameMap, caSubjectToNameMap);
            }
        }
    }

    public String getFingerprint() { return fingerprint; }
    public RaCertificateDetails getCertificate() { return raCertificateDetails; }
}
