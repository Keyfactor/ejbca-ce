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
package org.ejbca.core.ejb.ca.sign;

import java.security.cert.Certificate;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;


/**
 * @version $Id$
 *
 */
public abstract class SignSessionCommon extends CaTestCase{

    private static final Logger log = Logger.getLogger(SignSessionCommon.class);
    
    private static final AuthenticationToken internalAdmin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("SignSessionCommon"));
    
    protected static final String CERTPROFILE_PRIVKEYUSAGEPERIOD = "TestPrivKeyUsagePeriodCertProfile";
    protected static final String EEPROFILE_PRIVKEYUSAGEPERIOD = "TestPrivKeyUsagePeriodEEProfile";
    protected static final String USER_PRIVKEYUSAGEPERIOD = "fooprivkeyusageperiod";
    protected static final String DN_PRIVKEYUSAGEPERIOD = "C=SE,CN=testprivatekeyusage";
    

    protected static void createEndEntity(String username, int endEntityProfileId, int certificateProfileId, int caId) throws Exception{
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        // Make user that we know...
        if (!endEntityManagementSession.existsUser(username)) {
            endEntityManagementSession.addUser(internalAdmin, username, "foo123", "C=SE,CN="+username, null, username+"@anatom.se", false, endEntityProfileId,
                    certificateProfileId, EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.TOKEN_SOFT_PEM, 0, caId);
            if (log.isDebugEnabled()) {
                log.debug("created user: foo, foo123, C=SE, O=AnaTom, CN=foo");
            }
        } else {
            log.info("User " + username + " already exists, resetting status.");
            EndEntityInformation endEntity = new EndEntityInformation(username,  "C=SE,CN="+username,
                    caId, null, 
                    "foo@anatom.nu", EndEntityConstants.STATUS_NEW, EndEntityTypes.ENDUSER.toEndEntityType(),
                    endEntityProfileId, certificateProfileId, null, null, SecConst.TOKEN_SOFT_PEM, 0,
                    null);
            endEntity.setPassword("foo123");
            endEntityManagementSession.changeUser(internalAdmin, endEntity, false);            
            if (log.isDebugEnabled()) {
                log.debug("Reset status to NEW");
            }
        }
    }
    
    protected static void createEndEntity(String username, String endEntityProfileName, String certificateProfileName, int caId) throws Exception {
       
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
      
        
        final CertificateProfile certprof = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        certprof.setAllowKeyUsageOverride(true);

        if (certificateProfileSession.getCertificateProfile(certificateProfileName) == null) {
            certificateProfileSession.addCertificateProfile(internalAdmin, certificateProfileName, certprof);
        }
        final int fooCertProfile = certificateProfileSession.getCertificateProfileId(certificateProfileName);
        final EndEntityProfile profile = new EndEntityProfile(true);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, Integer.toString(fooCertProfile));
        if (endEntityProfileSession.getEndEntityProfile(endEntityProfileName) == null) {
            endEntityProfileSession.addEndEntityProfile(internalAdmin, endEntityProfileName, profile);
        }
        final int fooEEProfile = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
        createEndEntity(username, fooEEProfile, fooCertProfile, caId);  
    }
    
    protected static void cleanUpEndEntity(String username) throws AuthorizationDeniedException {
        EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);

       
        
        CertificateProfileSessionRemote certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        CertificateStoreSessionRemote storeSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

        EndEntityInformation endEntity = endEntityAccessSession.findUser(internalAdmin, username);
        try {
            endEntityProfileSession.removeEndEntityProfile(internalAdmin, endEntityProfileSession.getEndEntityProfileName(endEntity.getEndEntityProfileId()));           
            } catch (Exception e) { /* ignore */
            //NOPMD
        }
        try {
            certificateProfileSession.removeCertificateProfile(internalAdmin, certificateProfileSession.getCertificateProfileName(endEntity.getCertificateProfileId()));
        } catch (Exception e) { /* ignore */
            //NOPMD
        }
        List<Certificate> certs = EJBTools.unwrapCertCollection(storeSession.findCertificatesByUsername(username));
        for (Certificate certificate : certs) {
            try {
                internalCertStoreSession.removeCertificate(CertTools.getFingerprintAsString(certificate));
            } catch (Exception e) { /* ignore */
                //NOPMD
            }
        }

        try {
            endEntityManagementSession.deleteUser(internalAdmin, username);
        } catch (Exception e) { /* ignore */
            //NOPMD
        }
    }
    
}
