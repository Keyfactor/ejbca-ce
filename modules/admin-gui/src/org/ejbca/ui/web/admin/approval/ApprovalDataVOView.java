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
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.ejb.EJBException;
import javax.faces.application.Application;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.PublicAccessAuthenticationToken;
import org.cesecore.authentication.tokens.PublicWebPrincipal;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.WebPrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.approval.ApprovalDataText;
import org.ejbca.core.model.approval.ApprovalDataVO;
import org.ejbca.core.model.approval.ApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.AddEndEntityApprovalRequest;
import org.ejbca.core.model.approval.approvalrequests.EditEndEntityApprovalRequest;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.LinkView;
import org.ejbca.ui.web.jsf.configuration.EjbcaJSFHelper;

/**
 * Class representing the view of one ApprovalDataVO data
 * 
 * 
 * @version $Id$
 */
public class ApprovalDataVOView implements Serializable {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(ApprovalDataVOView.class);
	private final EjbLocalHelper ejbLocalHelper = new EjbLocalHelper();
    private ApprovalDataVO data;

    // Table of the translation constants in languagefile.xx.properties
    private static final String CERTSERIALNUMBER = "CERTSERIALNUMBER";
    private static final String ISSUERDN = "ISSUERDN";
    private static final String USERNAME = "USERNAME";

    public ApprovalDataVOView(final ApprovalDataVO data) {
        this.data = data;
    }

    public ApprovalDataVOView() { }

    public ApprovalRequest getApprovalRequest() {
        return data.getApprovalRequest();
    }
    
    public String getRequestDate() {
        return fastDateFormat(data.getRequestDate());
    }

    public String getExpireDate() {
        return fastDateFormat(data.getExpireDate());
    }
    
    private String fastDateFormat(final Date date) {
		return EjbcaJSFHelper.getBean().getEjbcaWebBean().formatAsISO8601(date);
    }

    public String getCaName() {
        final EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();
        if (data.getCAId() == ApprovalDataVO.ANY_CA) {
            return helpBean.getEjbcaWebBean().getText("ANYCA", true);
        }
        try {
            final CAInfo caInfo = ejbLocalHelper.getCaSession().getCAInfo(helpBean.getAdmin(), data.getCAId());
            if(caInfo != null) {
                return caInfo.getName();
            } else {
                log.error("Can not get CA with id: "+data.getCAId());
            }
		} catch (final AuthorizationDeniedException e) {
			log.error("Can not get CA with id: "+data.getCAId(), e);
		}
		return "Error";
    }

    public String getEndEntityProfileName() {
        final EjbcaJSFHelper helpBean = EjbcaJSFHelper.getBean();
        if (data.getEndEntityProfileId() == ApprovalDataVO.ANY_ENDENTITYPROFILE) {
            return helpBean.getEjbcaWebBean().getText("ANYENDENTITYPROFILE", true);
        }
        return ejbLocalHelper.getEndEntityProfileSession().getEndEntityProfileName(data.getEndEntityProfileId());
    }

    public String getRemainingApprovals() {
        return "" + data.getRemainingApprovals();
    }
    
    public ApprovalProfile getApprovalProfile() {
        return data.getApprovalProfile();
    }

    public String getApproveActionName() {
        return EjbcaJSFHelper.getBean().getEjbcaWebBean()
                .getText(ApprovalDataVO.APPROVALTYPENAMES.get(data.getApprovalRequest().getApprovalType()), true);
    }

    /**
     * Figures out a printable approval request admin, i.e. who was the originator of an approval request.
     * In case of a certificate authenticated entity, the CN, or full DN if no CN exists.
     * In case of Unauthenticated users accessing the RA "RA Web: remoteIp"
     * In case of Public Web "Public Web: remoteIp"
     * In case of protocols, f.ex SCEP "ScepServlet: remoteIp"
     * In case of username authentication, i.e. CLI "Command Line Tool: username"
     * other cases principal.toString()
     * 
     * @return UI presentable request admin String according to above
     */
    public String getRequestAdminName() {
        String retval = null;
        final Certificate cert = data.getApprovalRequest().getRequestAdminCert();
        final AuthenticationToken reqAdmin = data.getApprovalRequest().getRequestAdmin();
        if (cert != null) {
            final String dn = CertTools.getSubjectDN(cert);
            String o = CertTools.getPartFromDN(dn, "O");
            if (o == null) {
                o = "";
            } else {
                o = ", " + o;
            }
            retval = CertTools.getPartFromDN(dn, "CN") + o;
        } else {
            if (reqAdmin != null) {
                for (final Principal principal : reqAdmin.getPrincipals()) {
                    if (principal instanceof PublicAccessAuthenticationToken.PublicAccessPrincipal) {
                        // Unauthenticated users accessing the RA
                        final String ipAddress = principal.toString();
                        retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("RAWEB", true) + ": " + ipAddress;;
                        break;
                    } else if (principal instanceof PublicWebPrincipal) {
                        // Mostly self-registration in the Public Web
                        final String ipAddress = ((PublicWebPrincipal) principal).getClientIPAddress();
                        retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("PUBLICWEB", true) + ": " + ipAddress;
                        break;
                    } else if (principal instanceof WebPrincipal) {
                        // Other things, such as CMP, SCEP, etc. We can get here of requests require approval, such as PENDING and GETCERTINITIAL in SCEP
                        retval = principal.toString(); // e.g. "NameOfServlet: 198.51.100.123"
                        break;
                    } else if (principal instanceof UsernamePrincipal) {
                        final String username = principal.toString();
                        retval = EjbcaJSFHelper.getBean().getEjbcaWebBean().getText("CLITOOL", true) + ": " + username;
                        break;
                    } else {
                        retval = principal.toString(); // e.g. NestableAuthenticationToken for example                            
                        break;
                    }
                }
            } else {
                // Should hopefully never happen
                log.warn("Approval request where we can get no subjectDN and no request admin principal: " + data.getApprovalRequest());
                retval = "Unknown";
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("getRequestAdminName " + retval);
        }
        return retval;
    }

    public String getStatus() {
        final FacesContext context = FacesContext.getCurrentInstance();
        final Application app = context.getApplication();
        final ApproveActionManagedBean value = app.evaluateExpressionGet(context, "#{approvalActionManagedBean}", ApproveActionManagedBean.class);
        return value.getStatusText().get(Integer.valueOf(data.getStatus()));
    }

    public ApprovalDataVO getApproveActionDataVO() {
        return data;
    }

    public int getApprovalId() {
        return data.getApprovalId();
    }

    /**
     * Constructs JavaScript that opens up a new window and opens up actionview
     * there
     */
    public String getApproveActionWindowLink() {
        final String link = EjbcaJSFHelper.getBean().getEjbcaWebBean().getBaseUrl()
                + EjbcaJSFHelper.getBean().getEjbcaWebBean().getGlobalConfiguration().getAdminWebPath() + "approval/approvalaction.xhtml?uniqueId="
                + data.getId();
        return "window.open('" + link + "', 'ViewApproveAction', 'width=650,height=800,scrollbars=yes,toolbar=no,resizable=yes').focus()";
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
                        + "viewcertificate.xhtml?certsernoparameter="
                        + java.net.URLEncoder.encode(data.getReqadmincertsn() + "," + data.getReqadmincertissuerdn(), "UTF-8");
            } catch (final UnsupportedEncodingException e) {
                throw new EJBException(e);
            }
            retval = "window.open('" + link + "', 'ViewRequestorCertAction', 'width=800,height=800,scrollbars=yes,toolbar=no,resizable=yes').focus()";
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
        final List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
        for (final ApprovalDataText row : newTextRows) {
            if (row.getHeader().equals(CERTSERIALNUMBER) || row.getHeader().equals(ISSUERDN) || row.getHeader().equals(USERNAME)) {
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
        final List<LinkView> certificateLinks = new ArrayList<>();
        final List<String> certificateSerialNumbers = new ArrayList<>();
        final List<String> certificateIssuerDN = new ArrayList<>();
        final List<ApprovalDataText> newTextRows = getNewRequestDataAsText();

        for (final ApprovalDataText row : newTextRows) {
            if (row.getHeader().equals(CERTSERIALNUMBER)) {
                certificateSerialNumbers.add(row.getData());
            }
            if (row.getHeader().equals(ISSUERDN)) {
                certificateIssuerDN.add(row.getData());
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
                        + "viewcertificate.xhtml?certsernoparameter="
                        + java.net.URLEncoder.encode(certificateSerialNumbers.get(i) + "," + certificateIssuerDN.get(i), "UTF-8");
            } catch (final UnsupportedEncodingException e) {
                log.warn("UnsupportedEncoding creating approval data link. ", e);
            }
            certificateLinks.add(new LinkView(link, EjbcaJSFHelper.getBean().getEjbcaWebBean().getText(CERTSERIALNUMBER) + ": ",
                    certificateSerialNumbers.get(i), ""));
        }
        return certificateLinks;
    }

    public List<TextComparisonView> getTextListExceptLinks() {
        final ArrayList<TextComparisonView> textComparisonList = new ArrayList<>();
        final List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
        for (final ApprovalDataText row : newTextRows) {
            if (row.getHeader().equals(CERTSERIALNUMBER)
                    || row.getHeader().equals(ISSUERDN)) {
                continue;
            }
            String newString = "";
            try {
                newString = translateApprovalDataText(row);
            } catch (final ArrayIndexOutOfBoundsException e) {
                // Do nothing orgstring should be "";
            }
            textComparisonList.add(new TextComparisonView(null, newString));
        }
        return textComparisonList;
    }

    public List<TextComparisonView> getTextComparisonList() {
        final ArrayList<TextComparisonView> textComparisonList = new ArrayList<>();
        if (data.getApprovalRequest().getApprovalRequestType() == ApprovalRequest.REQUESTTYPE_COMPARING) {
            final List<ApprovalDataText> newTextRows = getNewRequestDataAsText();
            final List<ApprovalDataText> orgTextRows = getOldRequestDataAsText();
            int size = newTextRows.size();
            if (orgTextRows.size() > size) {
                size = orgTextRows.size();
            }
            for (int i = 0; i < size; i++) {
                String orgString = "";
                try {
                    orgString = translateApprovalDataText(orgTextRows.get(i));
                } catch (final IndexOutOfBoundsException e) {
                    // Do nothing orgstring should be "";
                }
                String newString = "";
                try {
                    newString = translateApprovalDataText(newTextRows.get(i));
                } catch (final IndexOutOfBoundsException e) {
                    // Do nothing orgstring should be "";
                }
                textComparisonList.add(new TextComparisonView(orgString, newString));
            }
        } else {
            for(final ApprovalDataText approvalDataText : getNewRequestDataAsText()) {
                textComparisonList.add(new TextComparisonView(null, translateApprovalDataText(approvalDataText)));
            }
        }
        return textComparisonList;
    }

    private String translateApprovalDataText(final ApprovalDataText data) {
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
    	final ApprovalRequest approvalRequest = data.getApprovalRequest();
    	final AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    	if (approvalRequest instanceof EditEndEntityApprovalRequest) {
    		return ((EditEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(ejbLocalHelper.getCaSession(),
    				ejbLocalHelper.getEndEntityProfileSession(), ejbLocalHelper.getCertificateProfileSession());
    	} else if (approvalRequest instanceof AddEndEntityApprovalRequest) {
    		return ((AddEndEntityApprovalRequest)approvalRequest).getNewRequestDataAsText(ejbLocalHelper.getCaSession(),
    				ejbLocalHelper.getEndEntityProfileSession(), ejbLocalHelper.getCertificateProfileSession());
    	} else {
    		return approvalRequest.getNewRequestDataAsText(admin);
    	}
    }

    private List<ApprovalDataText> getOldRequestDataAsText() {
    	final ApprovalRequest approvalRequest = data.getApprovalRequest();
    	final AuthenticationToken admin = EjbcaJSFHelper.getBean().getAdmin();
    	if (approvalRequest instanceof EditEndEntityApprovalRequest) {
    		return ((EditEndEntityApprovalRequest)approvalRequest).getOldRequestDataAsText(admin, ejbLocalHelper.getCaSession(),
    				ejbLocalHelper.getEndEntityProfileSession(), ejbLocalHelper.getCertificateProfileSession());
    	} else {
    		return approvalRequest.getOldRequestDataAsText(admin);
    	}
    }


}
