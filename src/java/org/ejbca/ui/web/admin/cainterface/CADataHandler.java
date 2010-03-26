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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.IllegalKeyStoreException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.XKMSCAServiceInfo;
import org.ejbca.core.model.ca.catoken.CATokenAuthenticationFailedException;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IRequestMessage;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.X509ResponseMessage;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.util.CertTools;
import org.ejbca.util.FileTools;

/**
 * A class help administrating CAs. 
 *
 * @author  TomSelleck
 * @version $Id$
 */
public class CADataHandler implements Serializable {
    private static final Logger log = Logger.getLogger(CADataHandler.class);

    
    /** Creates a new instance of CertificateProfileDataHandler */
    public CADataHandler(Admin administrator, 
                         ICAAdminSessionLocal caadminsession, 
                         IUserAdminSessionLocal adminsession, 
                         IRaAdminSessionLocal raadminsession, 
                         ICertificateStoreSessionLocal certificatesession,
                         IAuthorizationSessionLocal authorizationsession,
                         ICreateCRLSessionLocal crlSession,
                         EjbcaWebBean ejbcawebbean) {
                            
       this.caadminsession = caadminsession;           
       this.authorizationsession = authorizationsession;
       this.adminsession = adminsession;
       this.certificatesession = certificatesession;
       this.raadminsession = raadminsession;
       this.administrator = administrator;          
       this.crlSession = crlSession;
       this.info = ejbcawebbean.getInformationMemory();       
       this.ejbcawebbean = ejbcawebbean;
    }
    
  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */    
  public void createCA(CAInfo cainfo) throws CAExistsException, CATokenOfflineException, CATokenAuthenticationFailedException, AuthorizationDeniedException{
    caadminsession.createCA(administrator, cainfo);
    info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCAFromKeyStore(String caname, byte[] p12file, String keystorepass, String privkeypass, String privateSignatureKeyAlias,
		  String privateEncryptionKeyAlias) throws Exception {
    caadminsession.importCAFromKeyStore(administrator, caname, p12file, keystorepass, privkeypass, privateSignatureKeyAlias, privateEncryptionKeyAlias);  
    info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCACert(String caname, InputStream is) throws Exception {
	  Collection certs = null;
	  byte[] certbytes = FileTools.readInputStreamtoBuffer(is);
	  try {
		  certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes));
	  } catch (IOException e) {
		  log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
		  // See if it is a single binary certificate
		  Certificate cert = CertTools.getCertfromByteArray(certbytes);
		  certs = new ArrayList();
		  certs.add(cert);
	  }
	  caadminsession.importCACertificate(administrator, caname, certs);
	  info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void editCA(CAInfo cainfo) throws AuthorizationDeniedException{
    caadminsession.editCA(administrator, cainfo);  
    info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public boolean removeCA(int caid) throws AuthorizationDeniedException{
      
    boolean caidexits = this.adminsession.checkForCAId(administrator, caid) ||
                        this.certificatesession.existsCAInCertificateProfiles(administrator, caid) ||
                        this.raadminsession.existsCAInEndEntityProfiles(administrator, caid) ||
                        this.authorizationsession.existsCAInRules(administrator, caid);
     
    if(!caidexits){
      caadminsession.removeCA(administrator, caid);
      info.cAsEdited();
    }
    
    return !caidexits;
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public void renameCA(String oldname, String newname) throws CAExistsException, AuthorizationDeniedException{
    caadminsession.renameCA(administrator, oldname, newname);  
    info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.model.ca.caadmin.ICAAdminSessionLocal
   */  
  public CAInfoView getCAInfo(String name) throws Exception{
    CAInfoView cainfoview = null; 
    CAInfo cainfo = caadminsession.getCAInfo(administrator, name);
    if(cainfo != null) {
      cainfoview = new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    } 
    return cainfoview;
  }
  
  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public CAInfoView getCAInfo(int caid) throws Exception{
    // temporate        
    CAInfoView cainfoview = null; 
    CAInfo cainfo = caadminsession.getCAInfo(administrator, caid);
    if(cainfo != null) {
      cainfoview = new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    }
    return cainfoview;  
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public HashMap getCAIdToNameMap(){
    return info.getCAIdToNameMap();
  }
  
  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public byte[] makeRequest(int caid, Collection cachain, boolean setstatustowaiting, String keystorepass, boolean regenerateKeys) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
	  byte[] result = caadminsession.makeRequest(administrator, caid,cachain,setstatustowaiting,keystorepass,regenerateKeys);
	  return result;    
  }	    

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public byte[] signRequest(int caid, byte[] request, boolean usepreviouskey, boolean createlinkcert) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
	  byte[] result = caadminsession.signRequest(administrator, caid, request, usepreviouskey, createlinkcert);
	  return result;    
  }	    
  
  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public void receiveResponse(int caid, InputStream is) throws Exception{
	  try {
		  Certificate cert = null;
		  byte[] certbytes = FileTools.readInputStreamtoBuffer(is);
		  Collection cachain = null;
		  try {
			  Collection certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes));
			  Iterator iter = certs.iterator();
			  cert = (Certificate) iter.next();	
			  if (iter.hasNext()) {
				  // There is a complete certificate chain returned here
				  cachain = new ArrayList();
				  while (iter.hasNext()) {
					  Certificate chaincert = (Certificate) iter.next();
					  cachain.add(chaincert);
				  }
			  }
		  } catch (IOException e) {
			  log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
			  // See if it is a single binary certificate
			  cert = CertTools.getCertfromByteArray(certbytes);
		  }
		  X509ResponseMessage resmes = new X509ResponseMessage();
		  resmes.setCertificate(cert);
		  caadminsession.receiveResponse(administrator, caid, resmes, cachain);
		  info.cAsEdited(); 		  
	  } catch (Exception e) {
	      // log the error here, since otherwise it may be hidden by web pages...
		  log.error("Error receiving response: ", e);
		  throw e;
	  }
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public Certificate processRequest(CAInfo cainfo, IRequestMessage requestmessage) throws Exception {      
      Certificate returnval = null;
      IResponseMessage result = caadminsession.processRequest(administrator, cainfo, requestmessage);
      if(result instanceof X509ResponseMessage){
         returnval = ((X509ResponseMessage) result).getCertificate();      
      }            
      info.cAsEdited();
      
      return returnval;      
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public void renewCA(int caid, String keystorepass, boolean regenerateKeys) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CATokenOfflineException{
      caadminsession.renewCA(administrator, caid, keystorepass, regenerateKeys );
      info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public void revokeCA(int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException {
      caadminsession.revokeCA(administrator, caid, reason);
      info.cAsEdited();
  }
      
  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
 public void publishCA(int caid){
 	CAInfo cainfo = caadminsession.getCAInfo(administrator, caid);
 	Collection publishers = cainfo.getCRLPublishers();
 	// Publish ExtendedCAServices certificates as well
	Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
	while(iter.hasNext()){
		ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();	
		// Only publish certificates for active services
		if (next.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
			// The OCSP certificate is the same as the CA signing certificate
			if(next instanceof XKMSCAServiceInfo){
				List xkmscert = ((XKMSCAServiceInfo) next).getXKMSSignerCertificatePath();
				if (xkmscert != null) {
					caadminsession.publishCACertificate(administrator, xkmscert, publishers, cainfo.getSubjectDN());
				}
			}
			if(next instanceof CmsCAServiceInfo){
				List cmscert = ((CmsCAServiceInfo) next).getCertificatePath();
				if (cmscert != null) {
					caadminsession.publishCACertificate(administrator, cmscert, publishers, cainfo.getSubjectDN());
				}
			}
		}
	}  
    CertificateProfile certprofile = certificatesession.getCertificateProfile(administrator, cainfo.getCertificateProfileId());
    // A CA certificate is published where the CRL is published and if there is a publisher noted in the certificate profile 
    // (which there is probably not) 
    publishers.addAll(certprofile.getPublisherList());
    caadminsession.publishCACertificate(administrator, cainfo.getCertificateChain(), publishers, cainfo.getSubjectDN());
    crlSession.publishCRL(administrator, (Certificate) cainfo.getCertificateChain().iterator().next(), publishers, cainfo.getSubjectDN(), cainfo.getDeltaCRLPeriod()>0);
 }
 
 public void renewAndRevokeXKMSCertificate(int caid) throws CATokenOfflineException, CADoesntExistsException, UnsupportedEncodingException, IllegalKeyStoreException, AuthorizationDeniedException{
	 	CAInfo cainfo = caadminsession.getCAInfo(administrator, caid);
		Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
		while(iter.hasNext()){
		  ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();	
		  if(next instanceof XKMSCAServiceInfo){
		  	List xkmscerts = ((XKMSCAServiceInfo) next).getXKMSSignerCertificatePath();
		  	if (xkmscerts != null) {
			  	X509Certificate xkmscert = (X509Certificate)xkmscerts.get(0);
				certificatesession.revokeCertificate(administrator,xkmscert, cainfo.getCRLPublishers(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED, cainfo.getSubjectDN());	  	 
		  	}
		  	caadminsession.initExternalCAService(administrator, caid, next);
		  }
		}  
	 }
 
 public void renewAndRevokeCmsCertificate(int caid) throws CATokenOfflineException, CADoesntExistsException, UnsupportedEncodingException, IllegalKeyStoreException, AuthorizationDeniedException{
	 	CAInfo cainfo = caadminsession.getCAInfo(administrator, caid);
		Iterator iter = cainfo.getExtendedCAServiceInfos().iterator();
		while(iter.hasNext()){
		  ExtendedCAServiceInfo next = (ExtendedCAServiceInfo) iter.next();	
		  if(next instanceof CmsCAServiceInfo){
			  List cmscerts = ((CmsCAServiceInfo) next).getCertificatePath();
			  if (cmscerts != null) {
				  	X509Certificate cmscert = (X509Certificate)cmscerts.get(0);
					certificatesession.revokeCertificate(administrator,cmscert, cainfo.getCRLPublishers(), RevokedCertInfo.REVOKATION_REASON_UNSPECIFIED, cainfo.getSubjectDN());	  	 
			  }
			  caadminsession.initExternalCAService(administrator, caid, next);
		  }
		}  
	 }
 
 public void activateCAToken(int caid, String authorizationcode) throws AuthorizationDeniedException, CATokenAuthenticationFailedException, CATokenOfflineException, ApprovalException, WaitingForApprovalException {
   caadminsession.activateCAToken(administrator,caid,authorizationcode, raadminsession.loadGlobalConfiguration(administrator));	
 }
 
 public void deactivateCAToken(int caid) throws AuthorizationDeniedException, EjbcaException{
    caadminsession.deactivateCAToken(administrator, caid);	
 }
 
 public boolean isCARevoked(CAInfo cainfo){
	 boolean retval = false;
	 
	 if(cainfo != null){
	   retval = cainfo.getRevokationReason() != RevokedCertInfo.NOT_REVOKED;
	 }
	 return retval;
 }
   
  private ICAAdminSessionLocal           caadminsession; 
  private Admin                          administrator;
  private IAuthorizationSessionLocal     authorizationsession;
  private InformationMemory              info;
  private IUserAdminSessionLocal         adminsession;
  private IRaAdminSessionLocal           raadminsession; 
  private ICertificateStoreSessionLocal  certificatesession;                          
  private EjbcaWebBean                   ejbcawebbean;
  private ICreateCRLSessionLocal         crlSession;
}
