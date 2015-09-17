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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.ByteArrayInputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.rules.AccessRuleManagementSessionLocal;
import org.cesecore.authorization.user.AccessUserAspectManagerSessionLocal;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * A class help administrating CAs. 
 *
 * @version $Id$
 */
public class CADataHandler implements Serializable {
  
    private static final long serialVersionUID = 2132603037548273013L;

    private static final Logger log = Logger.getLogger(CADataHandler.class);

    private AuthenticationToken administrator;
    private InformationMemory info;
    
    private AccessRuleManagementSessionLocal accessRuleManagementSession;
    private AccessUserAspectManagerSessionLocal accessUserAspectManagerSession;
    private CAAdminSessionLocal caadminsession; 
    private CaSessionLocal caSession;
    private CertificateProfileSession certificateProfileSession;
    private EndEntityProfileSession endEntityProfileSession;
    private EndEntityManagementSessionLocal endEntitySession;

    private EjbcaWebBean ejbcawebbean;
    
    /** Creates a new instance of CADataHandler */
    public CADataHandler(final AuthenticationToken authenticationToken, final EjbLocalHelper ejb, final EjbcaWebBean ejbcawebbean) {
       this.accessRuleManagementSession = ejb.getAccessRuleManagementSession();
       this.accessUserAspectManagerSession = ejb.getAccessUserAspectSession();
       this.caadminsession = ejb.getCaAdminSession();
       this.caSession = ejb.getCaSession();
       this.endEntitySession = ejb.getEndEntityManagementSession();
       this.certificateProfileSession = ejb.getCertificateProfileSession();
       this.endEntityProfileSession = ejb.getEndEntityProfileSession();
       this.administrator = authenticationToken;
       this.info = ejbcawebbean.getInformationMemory();       
       this.ejbcawebbean = ejbcawebbean;
    }
    
  /**
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */    
  public void createCA(CAInfo cainfo) throws CAExistsException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, AuthorizationDeniedException, InvalidAlgorithmException{
    caadminsession.createCA(administrator, cainfo);
    info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCAFromKeyStore(String caname, byte[] p12file, String keystorepass, String privateSignatureKeyAlias, String privateEncryptionKeyAlias) throws Exception {
      final KeyStore ks = KeyStore.getInstance("PKCS12","BC");
      ks.load(new ByteArrayInputStream(p12file), keystorepass.toCharArray());
      if (privateSignatureKeyAlias.equals("")) {
          Enumeration<String> aliases = ks.aliases();
          if (aliases == null || !aliases.hasMoreElements()) {
              throw new Exception("This file does not contain any aliases.");
          }
          privateSignatureKeyAlias = (String)aliases.nextElement();
          if (aliases.hasMoreElements()) {
              while (aliases.hasMoreElements()) {
                  privateSignatureKeyAlias += " " + (String)aliases.nextElement();
              }
              throw new Exception("You have to specify any of the following aliases: " + privateSignatureKeyAlias);
          }
      }
      if ( privateEncryptionKeyAlias.equals("") ) {
          privateEncryptionKeyAlias = null;
      }
      caadminsession.importCAFromKeyStore(administrator, caname, p12file, keystorepass, keystorepass, privateSignatureKeyAlias, privateEncryptionKeyAlias);  
      info.cAsEdited();
  }

  /**
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCACertUpdate(int caId, byte[] certbytes) throws CertificateParsingException, CADoesntExistsException, CAExistsException, AuthorizationDeniedException, CertificateImportException {
      Collection<Certificate> certs = null;
      try {
          certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes));
      } catch (CertificateException e) {
          log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
          // See if it is a single binary certificate
          certs = new ArrayList<Certificate>();
          certs.add(CertTools.getCertfromByteArray(certbytes));
      }
      caadminsession.importCACertificateUpdate(administrator, caId, EJBTools.wrapCertCollection(certs));
      info.cAsEdited();
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCACert(String caname, byte[] certbytes) throws Exception {
	  Collection<Certificate> certs = null;
	  try {
		  certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes));
	  } catch (CertificateException e) {
		  log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
		  // See if it is a single binary certificate
		  Certificate cert = CertTools.getCertfromByteArray(certbytes);
		  certs = new ArrayList<Certificate>();
		  certs.add(cert);
	  }
	  caadminsession.importCACertificate(administrator, caname, EJBTools.wrapCertCollection(certs));
	  info.cAsEdited();
  }

  /**
   *  @throws CADoesntExistsException 
 * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void editCA(CAInfo cainfo) throws AuthorizationDeniedException, CADoesntExistsException{
	  CAInfo oldinfo = caSession.getCAInfo(administrator, cainfo.getCAId());
	  cainfo.setName(oldinfo.getName());
	  if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
	      cainfo.setSubjectDN(oldinfo.getSubjectDN());
	  }
	  caadminsession.editCA(administrator, cainfo);  
	  info.cAsEdited();
  }

    /**
     * Initializes a CA. The CA is updated with the values in caInfo,
     * its status is set to active and certificates are generated.
     * 
     * @param  caInfo CAInfo class containing updated information for the CA to initialize
     * @throws AuthorizationDeniedException if user was denied authorization to edit CAs 
     * @throws CryptoTokenOfflineException if the keystore defined by the cryptotoken in caInfo has no keys 
     * @throws InvalidKeyException if the cryptotoken owned by this CA lacks keystores
     * @throws CADoesntExistsException if the CA defined by caInfo doesn't exist.
     * @throws InvalidAlgorithmException 
     * @throws CryptoTokenAuthenticationFailedException 
     * @throws CAExistsException 
     * @throws CAOfflineException 
     * @throws CertificateRevokeException 
     * @throws UnsupportedEncodingException 
     */
    public void initializeCA(CAInfo caInfo) throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException, InvalidAlgorithmException {
        CAInfo oldinfo = caSession.getCAInfo(administrator, caInfo.getCAId());
        caInfo.setName(oldinfo.getName());
        
        caadminsession.initializeCa(administrator, caInfo);
        info.cAsEdited();
    }
  
  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public boolean removeCA(int caid) throws AuthorizationDeniedException{     
    boolean caidexits = this.endEntitySession.checkForCAId(caid) ||
                        this.certificateProfileSession.existsCAIdInCertificateProfiles(caid) ||
                        this.endEntityProfileSession.existsCAInEndEntityProfiles(caid) ||
                        (accessRuleManagementSession.existsCaInAccessRules(caid) && this.accessUserAspectManagerSession.existsCAInAccessUserAspects(caid));   
    if(!caidexits){
        caSession.removeCA(administrator, caid);
      info.cAsEdited();
    }
    
    return !caidexits;
  }

  /** @return true if CA with the new name already existed */  
  public boolean renameCA(int caId, String newname) throws AuthorizationDeniedException, CADoesntExistsException {
      if (caId!=0 && newname != null && newname.length()>0) {
          try {
              final String oldname = getCAIdToNameMap().get(Integer.valueOf(caId));
              caSession.renameCA(administrator, oldname, newname);
          } catch (CAExistsException e) {
              return true;
          }  
          info.cAsEdited();
      }
      return false;
  }

  public CAInfoView getCAInfo(String name) throws CADoesntExistsException, AuthorizationDeniedException {
    CAInfoView cainfoview = null; 
    CAInfo cainfo = caSession.getCAInfo(administrator, name);
    if(cainfo != null) {
      cainfoview = new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    } 
    return cainfoview;
  }
  
  public CAInfoView getCAInfoNoAuth(String name) throws CADoesntExistsException {
    CAInfoView cainfoview = null; 
    CAInfo cainfo = caSession.getCAInfoInternal(-1, name, true);
    if(cainfo != null) {
      cainfoview = new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    } 
    return cainfoview;
  }
  
  public CAInfoView getCAInfoNoAuth(final int caid) throws CADoesntExistsException {
      final CAInfo cainfo = caSession.getCAInfoInternal(caid);
      return new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    }
  

  public CAInfoView getCAInfo(final int caid) throws CADoesntExistsException, AuthorizationDeniedException {
    final CAInfo cainfo = caSession.getCAInfo(administrator, caid);
    return new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
  }

  /**
   *  @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */  
  public Map<Integer, String> getCAIdToNameMap(){
    return info.getCAIdToNameMap();
  }
  
  /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean */
  public byte[] makeRequest(int caid, byte[] caChainBytes, String nextSignKeyAlias) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
      List<Certificate> certChain = null;
      if (caChainBytes != null) {
          try {
              certChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(caChainBytes));
              if (certChain.size()==0) {
                  throw new Exception("Awkward code flow.."); // TODO
              }
          } catch (Exception e) {
              // Maybe it's just a single binary CA cert
              try {
                  Certificate cert = CertTools.getCertfromByteArray(caChainBytes);
                  certChain = new ArrayList<Certificate>();
                  certChain.add(cert);
              } catch (CertificateParsingException e2) {
                  // Ok.. so no chain was supplied.. we go ahead anyway..
                  throw new CADoesntExistsException("Invalid CA chain file.");
              }
          }
      }
      try {
          return caadminsession.makeRequest(administrator, caid, certChain, nextSignKeyAlias);
      } catch (CertPathValidatorException e) {
          throw new RuntimeException("Unexpected outcome.", e);
      }
  }

  /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean */
  public byte[] createAuthCertSignRequest(int caid, byte[] request) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException, CryptoTokenOfflineException{
      return caadminsession.createAuthCertSignRequest(administrator, caid, request);
  }     
  
  /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean#receiveResponse() */  
  public void receiveResponse(int caid, byte[] certBytes, String nextSignKeyAlias, boolean futureRollover) throws Exception{
	  try {
          final List<Certificate> certChain = new ArrayList<Certificate>();
		  try {
		      certChain.addAll(CertTools.getCertsFromPEM(new ByteArrayInputStream(certBytes)));
          } catch (CertificateException e) {
              log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
              // See if it is a single binary certificate
              certChain.add(CertTools.getCertfromByteArray(certBytes));
          }
		  if (certChain.size()==0) {
		      throw new Exception("No certificate(s) could be read.");
		  }
		  Certificate caCertificate = certChain.get(0);
		  final X509ResponseMessage resmes = new X509ResponseMessage();
		  resmes.setCertificate(caCertificate);
		  caadminsession.receiveResponse(administrator, caid, resmes, certChain.subList(1, certChain.size()), nextSignKeyAlias, futureRollover);
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
  public Certificate processRequest(CAInfo cainfo, RequestMessage requestmessage) throws Exception {      
      Certificate returnval = null;
      ResponseMessage result = caadminsession.processRequest(administrator, cainfo, requestmessage);
      if(result instanceof X509ResponseMessage){
         returnval = ((X509ResponseMessage) result).getCertificate();      
      }            
      info.cAsEdited();
      
      return returnval;      
  }

  public boolean renewCA(int caid, String nextSignKeyAlias, boolean createLinkCertificate) throws Exception {
      if (getCAInfo(caid).getCAInfo().getSignedBy() == CAInfo.SIGNEDBYEXTERNALCA) {
          return false;
      } else {
          if (getCAInfo(caid).getCAInfo().getCAType()==CAInfo.CATYPE_CVC) {
              // Force generation of link certificate for CVC CAs
              createLinkCertificate = true;
          }
          if (nextSignKeyAlias == null || nextSignKeyAlias.length()==0) {
              // Generate new keys
              caadminsession.renewCA(administrator, caid, true, null, createLinkCertificate);
          } else {
              // Use existing keys
              caadminsession.renewCA(administrator, caid, nextSignKeyAlias, null, createLinkCertificate);
          }
          info.cAsEdited();
          return true;
      }
  }

  /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean */
  public void revokeCA(int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException {
      caadminsession.revokeCA(administrator, caid, reason);
      info.cAsEdited();
  }
      
  /**
   *  @throws CADoesntExistsException 
 * @see org.ejbca.core.ejb.ca.caadmin.CAAdmiSessionBean
   */  
 public void publishCA(int caid) throws AuthorizationDeniedException, CADoesntExistsException {
 	CAInfo cainfo = caSession.getCAInfo(administrator, caid);
 	Collection<Integer> publishers = cainfo.getCRLPublishers();
 	// Publish ExtendedCAServices certificates as well
	Iterator<ExtendedCAServiceInfo> iter = cainfo.getExtendedCAServiceInfos().iterator();
	while(iter.hasNext()){
		ExtendedCAServiceInfo next = iter.next();	
		// Only publish certificates for active services
		if (next.getStatus() == ExtendedCAServiceInfo.STATUS_ACTIVE) {
			// The OCSP certificate is the same as the CA signing certificate
			if (next instanceof BaseSigningCAServiceInfo){
				List<Certificate> signingcert = ((BaseSigningCAServiceInfo) next).getCertificatePath();
				if (signingcert != null) {
					caadminsession.publishCACertificate(administrator, signingcert, publishers, cainfo.getSubjectDN());
				}
			}
		}
	}  
    CertificateProfile certprofile = certificateProfileSession.getCertificateProfile(cainfo.getCertificateProfileId());
    // A CA certificate is published where the CRL is published and if there is a publisher noted in the certificate profile 
    // (which there is probably not) 
    publishers.addAll(certprofile.getPublisherList());
    caadminsession.publishCACertificate(administrator, cainfo.getCertificateChain(), publishers, cainfo.getSubjectDN());
    caadminsession.publishCRL(administrator, (Certificate) cainfo.getCertificateChain().iterator().next(), publishers, cainfo.getSubjectDN(), cainfo.getDeltaCRLPeriod()>0);
 }
 
 /**
  * Performs a rollover from the current certificate to the next certificate. 
  * @throws AuthorizationDeniedException 
  * @throws CryptoTokenOfflineException
  * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSession#rolloverCA
  * */
 public void rolloverCA(int caid) throws CryptoTokenOfflineException, AuthorizationDeniedException {
     caadminsession.rolloverCA(administrator, caid);
 }
 
 public void renewAndRevokeCmsCertificate(int caid) throws CADoesntExistsException, CAOfflineException, CertificateRevokeException, AuthorizationDeniedException {
    caadminsession.renewAndRevokeCmsCertificate(administrator, caid);
 }
 
 public void activateCAToken(int caid) throws AuthorizationDeniedException, CryptoTokenAuthenticationFailedException, CryptoTokenOfflineException, ApprovalException, WaitingForApprovalException, CADoesntExistsException {
   caadminsession.activateCAService(administrator, caid);
 }
 
 public void deactivateCAToken(int caid) throws AuthorizationDeniedException, EjbcaException, IllegalCryptoTokenException, CADoesntExistsException, CryptoTokenAuthenticationFailedException{
    caadminsession.deactivateCAService(administrator, caid);	
 }
 
 public boolean isCARevoked(CAInfo cainfo){
	 boolean retval = false;
	 
	 if(cainfo != null){
	   retval = cainfo.getRevocationReason() != RevokedCertInfo.NOT_REVOKED;
	 }
	 return retval;
 }

}
