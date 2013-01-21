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

import java.io.Serializable;
import java.util.Collection;
import java.util.HashSet;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSession;
import org.ejbca.ui.web.admin.configuration.InformationMemory;

/**
 * A class handling the certificate type data. It saves and retrieves them
 * currently from a database.
 * 
 * @author TomSelleck
 * @version $Id$
 */
public class CertificateProfileDataHandler implements Serializable {

    private static final long serialVersionUID = 6293364591292667934L;

    private AccessControlSessionLocal authorizationsession;
    private CaSession caSession;
    private AuthenticationToken administrator;
    private InformationMemory info;
    private CertificateProfileSession certificateProfileSession;

    /** Creates a new instance of CertificateProfileDataHandler */
    public CertificateProfileDataHandler(AuthenticationToken administrator, AccessControlSessionLocal authorizationsession, CaSession caSession,
            CertificateProfileSession certificateProfileSession, InformationMemory info) {
        this.authorizationsession = authorizationsession;
        this.caSession = caSession;
        this.administrator = administrator;
        this.certificateProfileSession = certificateProfileSession;
        this.info = info;
    }

    /**
     * Method to add a certificate profile. Throws
     * CertificateProfileExitsException if profile already exists
     */
    public void addCertificateProfile(String name, CertificateProfile profile) throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (authorizedToProfile(profile, true)) {
            certificateProfileSession.addCertificateProfile(administrator, name, profile);
            this.info.certificateProfilesEdited();
        } else {
            throw new AuthorizationDeniedException("Not authorized to add certificate profile");
        }
    }

    /** Method to change a certificate profile. */
    public void changeCertificateProfile(String name, CertificateProfile profile) throws AuthorizationDeniedException {
        if (authorizedToProfile(profile, true)) {
            certificateProfileSession.changeCertificateProfile(administrator, name, profile);
            this.info.certificateProfilesEdited();
        } else {
            throw new AuthorizationDeniedException("Not authorized to edit certificate profile");
        }
    }

    /** Method to remove a end entity profile. */
    public void removeCertificateProfile(String name) throws AuthorizationDeniedException {
        if (authorizedToProfileName(name, true)) {
            certificateProfileSession.removeCertificateProfile(administrator, name);
            this.info.certificateProfilesEdited();
        } else {
            throw new AuthorizationDeniedException("Not authorized to remove certificate profile");
        }
    }

    /** Metod to rename a end entity profile */
    public void renameCertificateProfile(String oldname, String newname) throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (authorizedToProfileName(oldname, true)) {
            certificateProfileSession.renameCertificateProfile(administrator, oldname, newname);
            this.info.certificateProfilesEdited();
        } else {
            throw new AuthorizationDeniedException("Not authorized to rename certificate profile");
        }
    }

    public void cloneCertificateProfile(String originalname, String newname) throws CertificateProfileExistsException, AuthorizationDeniedException {
        if (authorizedToProfileName(originalname, false)) {
            try {
                // Use null as authorizedCaIds, so we will copy the profile exactly as the template, including available CAs
            	certificateProfileSession.cloneCertificateProfile(administrator, originalname, newname, null);
            	this.info.certificateProfilesEdited();
			} catch (CertificateProfileDoesNotExistException e) {
				// NOPMD: ignore do nothing
			}
        } else {
            throw new AuthorizationDeniedException("Not authorized to clone certificate profile");
        }
    }

    /** Method to get a reference to a end entity profile. */
    public CertificateProfile getCertificateProfile(int id) throws AuthorizationDeniedException {
        if (!authorizedToProfileId(id, false)) {
            throw new AuthorizationDeniedException("Not authorized to certificate profile");
        }
        return certificateProfileSession.getCertificateProfile(id);
    }

    public CertificateProfile getCertificateProfile(String profilename) throws AuthorizationDeniedException {
        if (!authorizedToProfileName(profilename, false)) {
            throw new AuthorizationDeniedException("Not authorized to certificate profile");
        }
        return certificateProfileSession.getCertificateProfile(profilename);
    }

    public int getCertificateProfileId(String profilename) {
        return certificateProfileSession.getCertificateProfileId(profilename);
    }

    /**
     * Help function that checks if administrator is authorized to edit profile
     * with given name.
     */
    private boolean authorizedToProfileName(String profilename, boolean editcheck) {
        CertificateProfile profile = certificateProfileSession.getCertificateProfile(profilename);
        return authorizedToProfile(profile, editcheck);
    }

    /**
     * Help function that checks if administrator is authorized to edit profile
     * with given name.
     */
    private boolean authorizedToProfileId(int profileid, boolean editcheck) {
        CertificateProfile profile = certificateProfileSession.getCertificateProfile(profileid);
        return authorizedToProfile(profile, editcheck);
    }

    /**
     * Help function that checks if administrator is authorized to edit profile.
     */
    private boolean authorizedToProfile(CertificateProfile profile, boolean editcheck) {
        boolean returnval = false;

        boolean issuperadministrator = authorizationsession.isAuthorizedNoLogging(administrator, StandardRules.ROLE_ROOT.resource());

        boolean editauth = true; // will be set to false if we should check it and we are not authorized
        if (editcheck) {
            editauth = authorizationsession.isAuthorizedNoLogging(administrator, "/ca_functionality/edit_certificate_profiles");
        }
        if (editauth) {
            HashSet<Integer> authorizedcaids = new HashSet<Integer>(caSession.getAvailableCAs(administrator));
            if (profile != null) {
                if (!issuperadministrator && profile.getType() != CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER) {
                    returnval = false;
                } else {
                    Collection<Integer> availablecas = profile.getAvailableCAs();
                    if (availablecas.contains(Integer.valueOf(CertificateProfile.ANYCA))) {
                        if (issuperadministrator && editcheck) {
                            returnval = true;
                        }
                        if (!editcheck) {
                            returnval = true;
                        }
                    } else {
                        returnval = authorizedcaids.containsAll(availablecas);
                    }
                }
            }        	
        }
        return returnval;
    }
}
