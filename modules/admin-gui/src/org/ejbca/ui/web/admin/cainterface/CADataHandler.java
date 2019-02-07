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
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.user.matchvalues.AccessMatchValue;
import org.cesecore.authorization.user.matchvalues.AccessMatchValueReverseLookupRegistry;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.CmsCertificatePathMissingException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.roles.AccessRulesHelper;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.member.RoleMember;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.BaseSigningCAServiceInfo;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;

/**
 * A class help administrating CAs.
 * <p>
 * Deprecated, we should move the methods here into managed beans or session beans (ECA-7588)
 *
 * @version $Id$
 * @deprecated since EJBCA 7.0.0
 */
@Deprecated
public class CADataHandler implements Serializable {
  
    private static final long serialVersionUID = 2132603037548273013L;

    private static final Logger log = Logger.getLogger(CADataHandler.class);

    private AuthenticationToken administrator;
    
    private RoleDataSessionLocal roleDataSession;
    private RoleMemberDataSessionLocal roleMemberDataSession;
    private CAAdminSessionLocal caadminsession; 
    private CaSessionLocal caSession;
    private CertificateProfileSession certificateProfileSession;
    private EndEntityProfileSession endEntityProfileSession;
    private EndEntityManagementSessionLocal endEntitySession;
    private final KeyValidatorSessionLocal keyValidatorSession;
    private final PublisherSessionLocal publisherSession;

    private EjbcaWebBean ejbcawebbean;
    
    /** Creates a new instance of CADataHandler */
    public CADataHandler(final AuthenticationToken authenticationToken, final EjbLocalHelper ejb, final EjbcaWebBean ejbcawebbean) {
       this.roleDataSession = ejb.getRoleDataSession();
       this.roleMemberDataSession = ejb.getRoleMemberDataSession();
       this.caadminsession = ejb.getCaAdminSession();
       this.caSession = ejb.getCaSession();
       this.endEntitySession = ejb.getEndEntityManagementSession();
       this.certificateProfileSession = ejb.getCertificateProfileSession();
       this.endEntityProfileSession = ejb.getEndEntityProfileSession();
       this.keyValidatorSession = ejb.getKeyValidatorSession();
       this.publisherSession = ejb.getPublisherSession();
       this.administrator = authenticationToken;
       this.ejbcawebbean = ejbcawebbean;
    }

  /**
   * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void importCACertUpdate(int caId, byte[] certbytes) throws CertificateParsingException, CADoesntExistsException, AuthorizationDeniedException, CertificateImportException, 
          CmsCertificatePathMissingException {
      Collection<Certificate> certs = null;
      try {
          certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes), Certificate.class);
      } catch (CertificateException e) {
          log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
          // See if it is a single binary certificate
          certs = new ArrayList<>();
          certs.add(CertTools.getCertfromByteArray(certbytes, Certificate.class));
      }
      caadminsession.updateCACertificate(administrator, caId, EJBTools.wrapCertCollection(certs));
  }

  /**
   *  @throws CADoesntExistsException 
 * @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean
   */
  public void editCA(CAInfo cainfo) throws AuthorizationDeniedException, CADoesntExistsException, CmsCertificatePathMissingException {
	  CAInfo oldinfo = caSession.getCAInfo(administrator, cainfo.getCAId());
	  cainfo.setName(oldinfo.getName());
	  if (cainfo.getStatus() != CAConstants.CA_UNINITIALIZED) {
	      cainfo.setSubjectDN(oldinfo.getSubjectDN());
	  }
	  caadminsession.editCA(administrator, cainfo);  
  }

    /**
     * Initializes a CA. The CA is updated with the values in caInfo,
     * its status is set to active and certificates are generated.
     * 
     * @param  caInfo CAInfo class containing updated information for the CA to initialize
     * @throws AuthorizationDeniedException if user was denied authorization to edit CAs 
     * @throws CryptoTokenOfflineException if the keystore defined by the cryptotoken in caInfo has no keys 
     * @throws CADoesntExistsException if the CA defined by caInfo doesn't exist.
     * @throws InvalidAlgorithmException 
     */
    public void initializeCA(CAInfo caInfo) throws AuthorizationDeniedException, CADoesntExistsException, CryptoTokenOfflineException, InvalidAlgorithmException {
        CAInfo oldinfo = caSession.getCAInfo(administrator, caInfo.getCAId());
        caInfo.setName(oldinfo.getName());
        
        caadminsession.initializeCa(administrator, caInfo);
    }
  
    /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean */  
    public boolean removeCA(final int caId) throws AuthorizationDeniedException{     
        final boolean caIdIsPresent = this.endEntitySession.checkForCAId(caId) ||
                this.certificateProfileSession.existsCAIdInCertificateProfiles(caId) ||
                this.endEntityProfileSession.existsCAInEndEntityProfiles(caId) ||
                isCaIdInUseByRoleOrRoleMember(caId);   
        if (!caIdIsPresent) {
            caSession.removeCA(administrator, caId);
        }
        return !caIdIsPresent;
    }

    /** @return true if the CA ID is in use by any Role's access rule or as RoleMember.tokenIssuerId */
    private boolean isCaIdInUseByRoleOrRoleMember(final int caId) {
        for (final Role role : roleDataSession.getAllRoles()) {
            if (role.getAccessRules().containsKey(AccessRulesHelper.normalizeResource(StandardRules.CAACCESS.resource() + caId))) {
                return true;
            }
            for (final RoleMember roleMember : roleMemberDataSession.findRoleMemberByRoleId(role.getRoleId())) {
                if (roleMember.getTokenIssuerId()==caId) {
                    // Do more expensive checks if it is a potential match
                    final AccessMatchValue accessMatchValue = AccessMatchValueReverseLookupRegistry.INSTANCE.getMetaData(
                            roleMember.getTokenType()).getAccessMatchValueIdMap().get(roleMember.getTokenMatchKey());
                    if (accessMatchValue.isIssuedByCa()) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

  /** @return true if CA with the new name already existed */  
  public boolean renameCA(int caId, String newname) throws AuthorizationDeniedException, CADoesntExistsException {
      if (caId!=0 && newname != null && newname.length()>0) {
          try {
              final String oldname = caSession.getCAIdToNameMap().get(caId);
              caSession.renameCA(administrator, oldname, newname);
          } catch (CAExistsException e) {
              return true;
          }  
      }
      return false;
  }

  public CAInfoView getCAInfo(final int caid) throws AuthorizationDeniedException {
    final CAInfo cainfo = caSession.getCAInfo(administrator, caid);
    return new CAInfoView(cainfo, ejbcawebbean, publisherSession.getPublisherIdToNameMap(), keyValidatorSession.getKeyValidatorIdToNameMap());
  }

  /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean */
  public byte[] makeRequest(int caid, byte[] caChainBytes, String nextSignKeyAlias) throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
      List<Certificate> certChain = null;
      if (caChainBytes != null) {
          try {
              certChain = CertTools.getCertsFromPEM(new ByteArrayInputStream(caChainBytes), Certificate.class);
              if (certChain.size()==0) {
                  throw new IllegalStateException("Certificate chain contained no certificates");
              }
          } catch (Exception e) {
              // Maybe it's just a single binary CA cert
              try {
                  Certificate cert = CertTools.getCertfromByteArray(caChainBytes, Certificate.class);
                  certChain = new ArrayList<>();
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
  
  /** @see org.ejbca.core.ejb.ca.caadmin.CAAdminSessionBean#receiveResponse */  
  public void receiveResponse(int caid, byte[] certBytes, String nextSignKeyAlias, boolean futureRollover) throws Exception{
	  try {
          final List<Certificate> certChain = new ArrayList<>();
		  try {
		      certChain.addAll(CertTools.getCertsFromPEM(new ByteArrayInputStream(certBytes), Certificate.class));
          } catch (CertificateException e) {
              log.debug("Input stream is not PEM certificate(s): "+e.getMessage());
              // See if it is a single binary certificate
              certChain.add(CertTools.getCertfromByteArray(certBytes, Certificate.class));
          }
		  if (certChain.size()==0) {
		      throw new Exception("No certificate(s) could be read.");
		  }
		  Certificate caCertificate = certChain.get(0);
		  final X509ResponseMessage resmes = new X509ResponseMessage();
		  resmes.setCertificate(caCertificate);
		  caadminsession.receiveResponse(administrator, caid, resmes, certChain.subList(1, certChain.size()), nextSignKeyAlias, futureRollover);
	  } catch (Exception e) {
	      // log the error here, since otherwise it may be hidden by web pages...
		  log.error("Error receiving response: ", e);
		  throw e;
	  }
  }

  public void renewCA(int caid, String nextSignKeyAlias, boolean createLinkCertificate) throws Exception {
      if (caSession.getCAInfo(administrator, caid).getCAType() == CAInfo.CATYPE_CVC) {
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
  }
  
  public void renewAndRenameCA(int caid, String nextSignKeyAlias, boolean createLinkCertificate, String newSubjectDn) throws Exception {
      if (nextSignKeyAlias == null || nextSignKeyAlias.length()==0) {
          // Generate new keys
          caadminsession.renewCANewSubjectDn(administrator, caid, true, null, createLinkCertificate, newSubjectDn);
      } else {
          // Use existing keys
          caadminsession.renewCANewSubjectDn(administrator, caid, nextSignKeyAlias, null, createLinkCertificate, newSubjectDn);
      }
  }

  /**
   *  @throws CADoesntExistsException 
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
    caadminsession.publishCRL(administrator, cainfo.getCertificateChain().iterator().next(), publishers, cainfo.getSubjectDN(), cainfo.getDeltaCRLPeriod()>0);
 }

 public boolean isCARevoked(CAInfo cainfo){
	 boolean retval = false;
	 
	 if(cainfo != null){
	   retval = RevokedCertInfo.isRevoked(cainfo.getRevocationReason());
	 }
	 return retval;
 }

}
