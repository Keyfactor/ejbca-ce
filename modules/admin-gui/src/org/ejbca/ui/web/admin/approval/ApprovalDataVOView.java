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

package org.ejbca.ui.web.admin.approval;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.Principal;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.EJBException;
import javax.faces.application.Application;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.Approval;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.DummyApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.AccumulativeApprovalProfile;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.LinkView;
import org.ejbca.ui.web.admin.configuration.EjbcaJSFHelper;

/**
 * Class representing the view of one ApprovalDataVO data
 * 
 * 
 * @version $Id$
 */
public class ApprovalDataVOView implements Serializable {

    private static byte[] dummycert = Base64.decode(("MIIDATCCAmqgAwIBAgIIczEoghAwc3EwDQYJKoZIhvcNAQEFBQAwLzEPMA0GA1UE"
            + "AxMGVGVzdENBMQ8wDQYDVQQKEwZBbmFUb20xCzAJBgNVBAYTAlNFMB4XDTAzMDky" + "NDA2NDgwNFoXDTA1MDkyMzA2NTgwNFowMzEQMA4GA1UEAxMHcDEydGVzdDESMBAG"
            + "A1UEChMJUHJpbWVUZXN0MQswCQYDVQQGEwJTRTCBnTANBgkqhkiG9w0BAQEFAAOB" + "iwAwgYcCgYEAnPAtfpU63/0h6InBmesN8FYS47hMvq/sliSBOMU0VqzlNNXuhD8a"
            + "3FypGfnPXvjJP5YX9ORu1xAfTNao2sSHLtrkNJQBv6jCRIMYbjjo84UFab2qhhaJ" + "wqJgkQNKu2LHy5gFUztxD8JIuFPoayp1n9JL/gqFDv6k81UnDGmHeFcCARGjggEi"
            + "MIIBHjAPBgNVHRMBAf8EBTADAQEAMA8GA1UdDwEB/wQFAwMHoAAwOwYDVR0lBDQw" + "MgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDBAYIKwYBBQUHAwUGCCsGAQUF"
            + "BwMHMB0GA1UdDgQWBBTnT1aQ9I0Ud4OEfNJkSOgJSrsIoDAfBgNVHSMEGDAWgBRj" + "e/R2qFQkjqV0pXdEpvReD1eSUTAiBgNVHREEGzAZoBcGCisGAQQBgjcUAgOgCQwH"
            + "Zm9vQGZvbzASBgNVHSAECzAJMAcGBSkBAQEBMEUGA1UdHwQ+MDwwOqA4oDaGNGh0" + "dHA6Ly8xMjcuMC4wLjE6ODA4MC9lamJjYS93ZWJkaXN0L2NlcnRkaXN0P2NtZD1j"
            + "cmwwDQYJKoZIhvcNAQEFBQADgYEAU4CCcLoSUDGXJAOO9hGhvxQiwjGD2rVKCLR4" + "emox1mlQ5rgO9sSel6jHkwceaq4A55+qXAjQVsuy76UJnc8ncYX8f98uSYKcjxo/"
            + "ifn1eHMbL8dGLd5bc2GNBZkmhFIEoDvbfn9jo7phlS8iyvF2YhC4eso8Xb+T7+BZ" + "QUOBOvc=").getBytes());
    
	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ApprovalDataVOView.class);
	private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private ApprovalDataVO data;
    private boolean initialized = false;

    // Table of the translation constants in languagefile.xx.properties
    private static final String CERTSERIALNUMBER = "CERTSERIALNUMBER";
    private static final String ISSUERDN = "ISSUERDN";
    private static final String USERNAME = "USERNAME";

    public ApprovalDataVOView(ApprovalDataVO data) {
        this.data = data;
        initialized = true;
    }

    /** Constructor used for initialization of dummy values. */
    public ApprovalDataVOView() { }

    public ApprovalRequest getApprovalRequest() {
        if(initialized) {
            return data.getApprovalRequest();
        }
        return null;
    }
    
    public String getRequestDate() {
        if (initialized) {
            return fastDateFormat(data.getRequestDate());
        }
        return fastDateFormat(new Date());
    }

    public String getExpireDate() {
        if (initialized) {
            return fastDateFormat(data.getExpireDate());
        }
        return fastDateFormat(new Date());
    }
    
    private String fastDateFormat(final Date date) {
		return EjbcaJSFHelper.getBean().getEjbcaWebBean().formatAsISO8601(date);
    }

    public String getCaName() {
        if (!initialized) {
            return "TestCA";
        }
        EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();
        if (data.getCAId() == ApprovalDataVO.ANY_CA) {
            return helpBean.getEjbcaWebBean().getText("ANYCA", true);
        }
        try {
			return ejbLocalHelper.getCaSession().getCAInfo(helpBean.getAdmin(), data.getCAId()).getName();
		} catch (CADoesntExistsException e) {
			log.error("Can not get CA with id: "+data.getCAId(), e);
		} catch (AuthorizationDeniedException e) {
			log.error("Can not get CA with id: "+data.getCAId(), e);
		}
		return "Error";
    }

    public String getEndEntityProfileName() {
        if (!initialized) {
            return "TestProfile";
        }
        EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();
        if (data.getEndEntityProfileiId() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
            return helpBean.getEjbcaWebBean().getText("ANYENDENTITYPROFILE", true);
        }
        return ejbLocalHelper.getEndEntityProfileSession().getEndEntityProfileName(data.getEndEntityProfileiId());
    }

    public String getRemainingApprovals() {
        if (!initialized) {
            return "1";
        }
        return "" + data.getRemainingApprovals();
    }
    
    public ApprovalProfile getApprovalProfile() {
        return data.getApprovalProfile();
    }

    public String getApproveActionName() {
        if (!initialized) {
            return "DummyAction";
        }
        return EjbcaJSFHelper.getBean().getEjbcaWebBean()
                .getText(ApprovalDataVO.APPROVALTYPENAMES[data.getApprovalRequest().getApprovalType()], true);
    }

    public String getRequestAdminName() {
        String retval;
        if (!initialized) {
            return "DummyAdmin";
        }
        final Certificate cert = data.getApprovalRequest().getRequestAdminCert();
        final AuthenticationToken reqAdmin = data.getApprovalRequest().getRequestAdmin();
        if (cert != null) {
            String dn = CertTools.getSubjectDN(cert);
            String o = CertTools.getPartFromDN(dn, "O");
            if (o == null) {
                o = "";
            } else {
                o = ", " + o;
            }
            retval = CertTools.getPartFromDN(dn, "CN") + o;
        } else {
            retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("CLITOOL", true); // Assume CLI if not match
            if (reqAdmin != null) {
                for (Principal principal : reqAdmin.getPrincipals()) {
                    if (principal instanceof PublicWebPrincipal) {
                        // Mostly self-registration
                        final String ipAddress = ((PublicWebPrincipal) principal).getClientIPAddress();
                        retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("PUBLICWEB", true) + ": " + ipAddress;
                        break;
                    } else if (principal instanceof WebPrincipal) {
                        // Other things, such as CMP, etc. We probably shouldn't ever get here, unless something is miss-configured.
                        retval = principal.getName(); // e.g. "NameOfServlet: 198.51.100.123"
                        break;
                    }
                }
            }
        }
        log.debug("getRequestAdminName " + retval);
        return retval;
    }

    public String getStatus() {
        if (!initialized) {
            return "EXPIRED";
        }
        FacesContext context = FacesContext.getCurrentInstance();
        Application app = context.getApplication();
        ApproveActionManagedBean value = app.evaluateExpressionGet(context, "#{approvalActionManagedBean}", ApproveActionManagedBean.class);
        return value.getStatusText().get(Integer.valueOf(data.getStatus()));
    }

    public ApprovalDataVO getApproveActionDataVO() {
        if (!initialized) {
            try {
            	X509Certificate certificate = CertTools.getCertfromByteArray(ApprovalDataVOView.dummycert, X509Certificate.class);
                AuthenticationToken token = new X509CertificateAuthenticationToken(certificate);
                AccumulativeApprovalProfile approvalProfile = new AccumulativeApprovalProfile("DummyApprovalProfile");
                approvalProfile.setNumberOfApprovalsRequired(2);
                DummyApprovalRequest req = new DummyApprovalRequest(token, null, ApprovalDataVO.ANY_ENDENTITYPROFILE, ApprovalDataVO.ANY_CA, false, approvalProfile);
                return new ApprovalDataVO(1, 1, ApprovalDataVO.APPROVALTYPE_DUMMY, 0, 0, "", "", ApprovalDataVO.STATUS_WAITINGFORAPPROVAL,
                        new ArrayList<Approval>(), req, new Date(), new Date());
            } catch (CertificateParsingException e) {
                log.error(e);
            }
        }
        return data;
    }

    public int getApprovalId() {
        if (!initialized) {
            return 1;
        }
        return data.getApprovalId();
    }

    /**
     * Constructs JavaScript that opens up a new window and opens up actionview
     * there
     */
    public String getApproveActionWindowLink() {
        String link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath() + "approval/approveaction.jsf?uniqueId="
                + data.getId();
        return "window.open('" + link + "', 'ViewApproveAction', 'width=1000,height=800,scrollbars=yes,toolbar=no,resizable=yes').focus()";
    }

    public boolean getShowViewRequestorCertLink() {
    	// Return true if there is a certificate
        return (data.getApprovalRequest().getRequestAdminCert() != null);
    }

    public String getViewRequestorCertLink() {
        String retval = "";
        if (data.getApprovalRequest().getRequestAdminCert() != null) {
            String link;
            try {
                link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                        + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
                        + "viewcertificate.jsp?certsernoparameter="
                        + java.net.URLEncoder.encode(data.getReqadmincertsn() + "," + data.getReqadmincertissuerdn(), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                throw new EJBException(e);
            }
            retval = "viewcert('" + link + "')";
        }
        return retval;
    }

    /**
     * Detect all certificate and user links from approval data based on the
     * static translations variables.
     * 
     * @return An array of Link-objects
     */
    public boolean isContainingLink() {
        if (!initialized) {
            return false;
        }
        List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
        int size = newTextRows.size();
        for (int i = 0; i < size; i++) {
            if (((ApprovalDataText) newTextRows.get(i)).getHeader().equals(CERTSERIALNUMBER)
                    || ((ApprovalDataText) newTextRows.get(i)).getHeader().equals(ISSUERDN)
                    || ((ApprovalDataText) newTextRows.get(i)).getHeader().equals(USERNAME)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Extract all certificate and user links from approval data based on the
     * static translations variables.
     * 
     * @return An array of Link-objects
     */
    public List<LinkView> getApprovalDataLinks() {
        List<LinkView> certificateLinks = new ArrayList<LinkView>();
        List<String> certificateSerialNumbers = new ArrayList<String>();
        List<String> certificateIssuerDN = new ArrayList<String>();
        List<ApprovalDataText> newTextRows = getNewRequestDataAsText();

        for (int i = 0; i < newTextRows.size(); i++) {
            if (((ApprovalDataText) newTextRows.get(i)).getHeader().equals(CERTSERIALNUMBER)) {
                certificateSerialNumbers.add(((ApprovalDataText) newTextRows.get(i)).getData());
            }
            if (((ApprovalDataText) newTextRows.get(i)).getHeader().equals(ISSUERDN)) {
                certificateIssuerDN.add(((ApprovalDataText) newTextRows.get(i)).getData());
            }
        }
        if (certificateIssuerDN.size() != certificateSerialNumbers.size()) {
            // Return an empty array if we have a mismatch
            return certificateLinks;
        }
        String link = null;
        for (int i = 0; i < certificateSerialNumbers.size(); i++) {
            try {
                link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                        + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath()
                        + "viewcertificate.jsp?certsernoparameter="
                        + java.net.URLEncoder.encode(certificateSerialNumbers.get(i) + "," + certificateIssuerDN.get(i), "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.warn("UnsupportedEncoding creating approval data link. ", e);
            }
            certificateLinks.add(new LinkView(link, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(CERTSERIALNUMBER) + ": ",
                    (String) certificateSerialNumbers.get(i), ""));
        }
        return certificateLinks;
    }

    public List<TextComparisonView> getTextListExceptLinks() {
        ArrayList<TextComparisonView> textComparisonList = new ArrayList<TextComparisonView>();
        if (!initialized) {
            return textComparisonList;
        }
        List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
        int size = newTextRows.size();
        for (int i = 0; i < size; i++) {
            if (((ApprovalDataText) newTextRows.get(i)).getHeader().equals(CERTSERIALNUMBER)
                    || ((ApprovalDataText) newTextRows.get(i)).getHeader().equals(ISSUERDN)) {
                continue;
            }
            String newString = "";
            try {
                newString = translateApprovalDataText((ApprovalDataText) newTextRows.get(i));
            } catch (ArrayIndexOutOfBoundsException e) {
                // Do nothing orgstring should be "";
            }
            textComparisonList.add(new TextComparisonView(null, newString));
        }
        return textComparisonList;
    }

    public List<TextComparisonView> getTextComparisonList() {
        ArrayList<TextComparisonView> textComparisonList = new ArrayList<TextComparisonView>();
        if (!initialized) {
            return textComparisonList;
        }
        if (data.getApprovalRequest().getApprovalRequestType() == ApprovalRequest.REQUESTTYPE_COMPARING) {
            List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
            List<ApprovalDataText> orgTextRows = getOldRequestDataAsText();
            int size = newTextRows.size();
            if (orgTextRows.size() > size) {
                size = orgTextRows.size();
            }
            for (int i = 0; i < size; i++) {
                String orgString = "";
                try {
                    orgString = translateApprovalDataText((ApprovalDataText) orgTextRows.get(i));
                } catch (ArrayIndexOutOfBoundsException e) {
                    // Do nothing orgstring should be "";
                }
                String newString = "";
                try {
                    newString = translateApprovalDataText((ApprovalDataText) newTextRows.get(i));
                } catch (ArrayIndexOutOfBoundsException e) {
                    // Do nothing orgstring should be "";
                }
                textComparisonList.add(new TextComparisonView(orgString, newString));
            }
        } else {
            for(ApprovalDataText approvalDataText : getNewRequestDataAsText()) {
                textComparisonList.add(new TextComparisonView(null, translateApprovalDataText(approvalDataText)));
            }
        }
        return textComparisonList;
    }

    private String translateApprovalDataText(ApprovalDataText data) {
        String retval = "";
        if (data.isHeaderTranslateable()) {
            retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(data.getHeader(), true);
        } else {
            retval = data.getHeader();
        }
        if (data.isDataTranslatable()) {
            retval += " : " + EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(data.getData(), true);
        } else {
            retval += " : " + data.getData();
        }
        return retval;
    }
    
    private List<ApprovalDataText> getNewRequestDataAsText() {
    	ApprovalRequest approvalRequest = data.getApprovalRequest();
    	AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    	if (approvalRequest instanceof EditEndEntityApprovalRequest) {
    		return ((EditEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(ejbLocalHelper.getCaSession(),
    				ejbLocalHelper.getEndEntityProfileSession(), ejbLocalHelper.getCertificateProfileSession(), ejbLocalHelper.getHardTokenSession());
    	} else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
    		return ((AddEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(ejbLocalHelper.getCaSession(),
    				ejbLocalHelper.getEndEntityProfileSession(), ejbLocalHelper.getCertificateProfileSession(), ejbLocalHelper.getHardTokenSession());
    	} else {
    		return approvalRequest.getNewRequestDataAsText(admin);
    	}
    }

    private List<ApprovalDataText> getOldRequestDataAsText() {
    	ApprovalRequest approvalRequest = data.getApprovalRequest();
    	AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    	if (approvalRequest instanceof EditEndEntityApprovalRequest) {
    		return ((EditEndEntityApprovalRequest)approvalRequest).getOldRequestDataAsText(admin, ejbLocalHelper.getCaSession(),
    				ejbLocalHelper.getEndEntityProfileSession(), ejbLocalHelper.getCertificateProfileSession(), ejbLocalHelper.getHardTokenSession());
    	} else {
    		return approvalRequest.getOldRequestDataAsText(admin);
    	}
    }


}
