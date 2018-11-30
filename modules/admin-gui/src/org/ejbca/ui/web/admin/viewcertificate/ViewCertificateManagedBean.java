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
package org.ejbca.ui.web.admin.viewcertificate;

import java.beans.Beans;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import javax.faces.bean.ManagedBean;
import javax.faces.bean.SessionScoped;
import javax.faces.context.FacesContext;
import javax.faces.event.ComponentSystemEvent;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.cainterface.CAInterfaceBean;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;

/**
 * JavaServer Faces Managed Bean for managing viewcertificate view.
 * Session scoped and will cache the user preferences.
 *
 * @version $Id: ViewCertificateManagedBean.java 30605 2018-11-23 10:01:15Z tarmo_r_helmes $
 */
@SessionScoped
@ManagedBean(name="viewCertificateMBean")
public class ViewCertificateManagedBean extends BaseManagedBean implements Serializable {

    private static final String CA_BEAN_ATTRIBUTE = "caBean";
    private static final String RA_BEAN_ATTRIBUTE = "rabean";
    
    private static final long serialVersionUID = 1L;
    
    private static final String CA_ID_PARAMETER = "caid";
    
    private static final String USER_PARAMETER             = "username";
    private static final String CERTSERNO_PARAMETER        = "certsernoparameter";
    private static final String CACERT_PARAMETER           = "caid";
    private static final String HARDTOKENSN_PARAMETER      = "tokensn";
    private static final String SERNO_PARAMETER            = "serno";
    private static final String ISSUER_PARAMETER           = "issuer";
    private static final String CADN_PARAMETER             = "cadn";

    private static final String BUTTON_CLOSE               = "buttonclose"; 
    private static final String BUTTON_VIEW_NEWER          = "buttonviewnewer"; 
    private static final String BUTTON_VIEW_OLDER          = "buttonviewolder";
    private static final String BUTTON_REVOKE              = "buttonrevoke";
    private static final String BUTTON_UNREVOKE            = "buttonunrevoke";
    private static final String BUTTON_RECOVERKEY          = "buttonrekoverkey";
    private static final String BUTTON_REPUBLISH           = "buttonrepublish";

    private static final String CHECKBOX_DIGITALSIGNATURE  = "checkboxdigitalsignature";
    private static final String CHECKBOX_NONREPUDIATION    = "checkboxnonrepudiation";
    private static final String CHECKBOX_KEYENCIPHERMENT   = "checkboxkeyencipherment";
    private static final String CHECKBOX_DATAENCIPHERMENT  = "checkboxdataencipherment";
    private static final String CHECKBOX_KEYAGREEMENT      = "checkboxkeyagreement";
    private static final String CHECKBOX_KEYCERTSIGN       = "checkboxkeycertsign";
    private static final String CHECKBOX_CRLSIGN           = "checkboxcrlsign";
    private static final String CHECKBOX_ENCIPHERONLY      = "checkboxencipheronly";
    private static final String CHECKBOX_DECIPHERONLY      = "checkboxdecipheronly";

    private static final String SELECT_REVOKE_REASON       = "selectrevocationreason";

    private static final String CHECKBOX_VALUE             = "true";

    private static final String HIDDEN_INDEX               = "hiddenindex";
    
    private boolean noparameter = true;
    private boolean notauthorized = true;
    private boolean cacerts = false;
    private boolean useKeyRecovery = false;   
    private CertificateView certificateData = null;
    private String certificateSerNo = null;
    private String userName = null;         
    private String tokenSn = null;
    private String message = null;
    private int numberOfCertificates = 0;
    private int currentIndex = 0;
    private final int row = 0; 
    private final int columnwidth = 150;
    private int caId = 0;
    
    private EjbcaWebBean ejbcaBean;
    private CAInterfaceBean caBean;
    private RAInterfaceBean raBean;
    
    private String caName;
    private String formattedCertSn;
    private String unescapedRdnValue;
    
    // Authentication check and audit log page access request
    public void initialize(final ComponentSystemEvent event) throws Exception {
        // Invoke on initial request only
        if (!FacesContext.getCurrentInstance().isPostback()) {
            final HttpServletRequest request = (HttpServletRequest)FacesContext.getCurrentInstance().getExternalContext().getRequest();
            
            ejbcaBean = getEjbcaWebBean();
            initCaBean(request);
            initRaBean(request);
            
            final GlobalConfiguration globalconfiguration = ejbcaBean.initialize(request, AccessRulesConstants.ROLE_ADMINISTRATOR); 
            
            final String caIdParameter = request.getParameter(CA_ID_PARAMETER);
            if (caIdParameter != null) {
                caId = Integer.parseInt(caIdParameter);
                
            }
            
            raBean.initialize(request, ejbcaBean);
            caBean.initialize(ejbcaBean);

            useKeyRecovery = globalconfiguration.getEnableKeyRecovery() && ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_KEYRECOVERY);
            RequestHelper.setDefaultCharacterEncoding(request);
            
            parseRequest(request);
            
            caName = caBean.getName(caId);
            formattedCertSn = raBean.getFormatedCertSN(certificateData);
            unescapedRdnValue = certificateData.getUnescapedRdnValue(certificateData.getIssuerDN());
            
            
            
            /* TODO:  
  <%if(noparameter){%>
  <div class="message alert"><%=ejbcawebbean.getText("YOUMUSTSPECIFYCERT") %></div> 
  <% } 
     else{
      if(notauthorized){%>
  <div class="message alert"><%=ejbcawebbean.getText("NOTAUTHORIZEDTOVIEWCERT") %></div> 
  <%   } 
       else{
         if(certificatedata == null){%>
  <div class="message alert"><%=ejbcawebbean.getText("CERTIFICATEDOESNTEXIST") %></div> 
    <%   }
         else{           
   if(message != null){ %>
      <div class="message alert"><%=ejbcawebbean.getText(message) %></div> 
  <% } %>
 
 */
             
        }
    }
    

    private void initCaBean(final HttpServletRequest request) throws Exception {
        caBean = (CAInterfaceBean) request.getSession().getAttribute(CA_BEAN_ATTRIBUTE);
        if ( caBean == null ) {
            try {
                caBean = (CAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
            } catch (final ClassNotFoundException exc) {
                throw new ServletException(exc.getMessage());
            }catch (final Exception exc) {
                throw new ServletException (" Cannot create bean of class "+CAInterfaceBean.class.getName(), exc);
            }
            request.getSession().setAttribute(CA_BEAN_ATTRIBUTE, caBean);
        }
        try{
            caBean.initialize(ejbcaBean);
        } catch(final Exception e){
            throw new java.io.IOException("Error initializing AdminIndexMBean");
        }
    }
    
    private void initRaBean(final HttpServletRequest request) throws ServletException {
        final HttpSession session = request.getSession();
        RAInterfaceBean raBean = (RAInterfaceBean) session.getAttribute(RA_BEAN_ATTRIBUTE);
        if (raBean == null) {
            try {
                raBean = (RAInterfaceBean) Beans.instantiate(Thread.currentThread().getContextClassLoader(),
                        org.ejbca.ui.web.admin.rainterface.RAInterfaceBean.class.getName());
            } catch (final ClassNotFoundException e) {
                throw new ServletException(e);
            } catch (final Exception e) {
                throw new ServletException("Unable to instantiate RAInterfaceBean", e);
            }
            try {
                raBean.initialize(request, ejbcaBean);
            } catch (final Exception e) {
                throw new ServletException("Cannot initialize RAInterfaceBean", e);
            }
            session.setAttribute(RA_BEAN_ATTRIBUTE, raBean);
        }
        this.raBean = raBean;
    }

    private void parseRequest(final HttpServletRequest request) throws AuthorizationDeniedException, CADoesntExistsException, UnsupportedEncodingException {
        if(request.getParameter(HARDTOKENSN_PARAMETER) != null && request.getParameter(USER_PARAMETER ) != null) {
            noparameter = false;
            if (ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
                notauthorized = false;
                userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
                tokenSn  = request.getParameter(HARDTOKENSN_PARAMETER);
                raBean.loadTokenCertificates(tokenSn);
            }
         }

         if(request.getParameter(USER_PARAMETER ) != null && request.getParameter(HARDTOKENSN_PARAMETER) == null) {
            noparameter = false;
            if (ejbcaBean.isAuthorizedNoLogSilent(AccessRulesConstants.REGULAR_VIEWCERTIFICATE)) {
                notauthorized = false;
                userName = java.net.URLDecoder.decode(request.getParameter(USER_PARAMETER),"UTF-8");
                raBean.loadCertificates(userName);
            }
         }

         if(request.getParameter(CERTSERNO_PARAMETER ) != null){     
               final String certSernoParam = java.net.URLDecoder.decode(request.getParameter(CERTSERNO_PARAMETER), "UTF-8");
               if (certSernoParam != null) {
                   final String[] certdata = ejbcaBean.getCertSernoAndIssuerdn(certSernoParam);
                   if (certdata != null && certdata.length > 0) {
                       raBean.loadCertificates(new BigInteger(certdata[0], 16),certdata[1]);
                   }
               }
            notauthorized = false;
            noparameter = false;
         }
         
         if (request.getParameter(SERNO_PARAMETER) != null && request.getParameter(CACERT_PARAMETER) != null) {
                certificateSerNo = request.getParameter(SERNO_PARAMETER);
                caId = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
                notauthorized = false;
                noparameter = false;
                raBean.loadCertificates(new BigInteger(certificateSerNo,16), caId);
         } else if (request.getParameter(CACERT_PARAMETER ) != null) {
            caId = Integer.parseInt(request.getParameter(CACERT_PARAMETER));
            if (request.getParameter(BUTTON_VIEW_NEWER) == null && request.getParameter(BUTTON_VIEW_OLDER) == null) {
                raBean.loadCACertificates(caBean.getCACertificates(caId)); 
                numberOfCertificates = raBean.getNumberOfCertificates();
                if(numberOfCertificates > 0) {
                    currentIndex = 0;
                }
                notauthorized = false;
              noparameter = false;
            }
            cacerts = true;
         }
         if(!noparameter){  
            if(request.getParameter(BUTTON_VIEW_NEWER) == null && request.getParameter(BUTTON_VIEW_OLDER) == null && 
               request.getParameter(BUTTON_REVOKE) == null && request.getParameter(BUTTON_RECOVERKEY) == null &&
               request.getParameter(BUTTON_REPUBLISH) == null ){
               numberOfCertificates = raBean.getNumberOfCertificates();
               if(numberOfCertificates > 0)
                 certificateData = raBean.getCertificate(currentIndex);
           }
          }
          if(request.getParameter(BUTTON_REVOKE) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts){
            currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
            noparameter=false;
            final int reason = Integer.parseInt(request.getParameter(SELECT_REVOKE_REASON));
            certificateData = raBean.getCertificate(currentIndex);
            if(!cacerts && raBean.authorizedToRevokeCert(certificateData.getUsername()) && ejbcaBean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_REVOKEENDENTITY) 
               && (!certificateData.isRevoked() || certificateData.isRevokedAndOnHold()) ) {
               try {
                   raBean.revokeCert(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped(), certificateData.getUsername(),reason);
               } catch (final org.ejbca.core.model.approval.ApprovalException e) {
                   message = "THEREALREADYEXISTSAPPOBJ";
               } catch (final org.ejbca.core.model.approval.WaitingForApprovalException e) {
                   message = "REQHAVEBEENADDEDFORAPPR";
               }
            }
            try {
              if (tokenSn !=null) {
                raBean.loadTokenCertificates(tokenSn);
              } else {
                if(userName != null) {
                  raBean.loadCertificates(userName);
                } else {
                  raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
                }
              }
              notauthorized = false;
            } catch(final AuthorizationDeniedException e) {
                
            }
            numberOfCertificates = raBean.getNumberOfCertificates();
            certificateData = raBean.getCertificate(currentIndex);
          }
            //-- Pushed unrevoke button
           if (request.getParameter(BUTTON_UNREVOKE) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts) {
           
               currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
               noparameter = false;
               certificateData = raBean.getCertificate(currentIndex);

               if (!cacerts && raBean.authorizedToRevokeCert(certificateData.getUsername()) 
                   && ejbcaBean.isAuthorizedNoLog(AccessRulesConstants.REGULAR_REVOKEENDENTITY) && certificateData.isRevokedAndOnHold()) {
                       //-- call to unrevoke method
                       try {
                           raBean.unrevokeCert(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped(), certificateData.getUsername());
                       } catch (final org.ejbca.core.model.approval.ApprovalException e) {
                           message = "THEREALREADYEXISTSAPPOBJ";
                       } catch (final org.ejbca.core.model.approval.WaitingForApprovalException e) {
                           message = "REQHAVEBEENADDEDFORAPPR";
                       }
               }
               
               try {
                   if (tokenSn != null) {
                       raBean.loadTokenCertificates(tokenSn);
                   } else {
                       if (userName != null) {
                           raBean.loadCertificates(userName);
                       } else {
                           raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
                       }
                   }
                   notauthorized = false;
               } catch (final AuthorizationDeniedException e) {
                   
               }
               
               numberOfCertificates = raBean.getNumberOfCertificates();
               certificateData = raBean.getCertificate(currentIndex);
           }
          
          if (request.getParameter(BUTTON_RECOVERKEY) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts) {
            // Mark certificate for key recovery.
            currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
            noparameter = false;
            certificateData = raBean.getCertificate(currentIndex);
            if (!cacerts && raBean.keyRecoveryPossible(certificateData.getCertificate(), certificateData.getUsername()) && useKeyRecovery) {
                try {
                    raBean.markForRecovery(certificateData.getUsername(), certificateData.getCertificate()); 
                  } catch (final org.ejbca.core.model.approval.ApprovalException e){
                      message = "THEREALREADYEXISTSAPPROVAL";
                  } catch (final org.ejbca.core.model.approval.WaitingForApprovalException e) {
                      message = "REQHAVEBEENADDEDFORAPPR";
                  }
            }
            try {
              if (tokenSn !=null) {
               raBean.loadTokenCertificates(tokenSn);
              } else { 
                if(userName != null) {
                  raBean.loadCertificates(userName);
                } else {
                  raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
                }
              }
              notauthorized = false;
            } catch(final AuthorizationDeniedException e) {
                
            }
            numberOfCertificates = raBean.getNumberOfCertificates();
            certificateData = raBean.getCertificate(currentIndex);
          }
          if (request.getParameter(BUTTON_REPUBLISH) != null && request.getParameter(HIDDEN_INDEX)!= null && !cacerts) {
            // Mark certificate for key recovery.
            currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX));
            noparameter = false;
            certificateData = raBean.getCertificate(currentIndex);
            message = caBean.republish(certificateData); 
            try{
              if (tokenSn !=null) {
                raBean.loadTokenCertificates(tokenSn);
              } else { 
                if(userName != null) {
                  raBean.loadCertificates(userName);
                } else {
                  raBean.loadCertificates(certificateData.getSerialNumberBigInt(), certificateData.getIssuerDNUnEscaped());
                }
              }
              notauthorized = false;
            } catch(final AuthorizationDeniedException e) {
                
            }
            numberOfCertificates = raBean.getNumberOfCertificates();
          }
           
           if(request.getParameter(BUTTON_VIEW_NEWER) != null){
              numberOfCertificates = raBean.getNumberOfCertificates();
              noparameter=false;
              if(request.getParameter(HIDDEN_INDEX)!= null){
                currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX)) -1;
                if(currentIndex < 0){
                  currentIndex = 0;
                }
                certificateData = raBean.getCertificate(currentIndex);
                notauthorized = false;
              }
           }
           if(request.getParameter(BUTTON_VIEW_OLDER) != null){
              numberOfCertificates = raBean.getNumberOfCertificates();
              noparameter=false;
              if(request.getParameter(HIDDEN_INDEX)!= null){
                currentIndex = Integer.parseInt(request.getParameter(HIDDEN_INDEX)) + 1;
                if(currentIndex > numberOfCertificates -1){
                  currentIndex = numberOfCertificates;
                }
                certificateData = raBean.getCertificate(currentIndex);
                notauthorized = false;
              }
           }
    }
    
    public boolean isCacerts() {
        return cacerts;
    }
    
    public CertificateView getCertificateData() {
        return certificateData;
    }
    
    public String getCaName() {
        return caName;
    }
    
    public int getCaId() {
        return caId;
    }


    public String getTokenSn() {
        return tokenSn;
    }
    
    public int getNumberOfCertificates() {
        return numberOfCertificates;
    }


    public int getCurrentIndex() {
        return currentIndex;
    }    

    public int getNextIndex() {
        return currentIndex + 1;
    }
    
    public String getFormattedCertSn() {
        return formattedCertSn;
    }
    
    public String getUnescapedRdnValue() {
        return unescapedRdnValue;
    }

    
}
