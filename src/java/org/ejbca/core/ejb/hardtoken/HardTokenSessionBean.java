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

package org.ejbca.core.ejb.hardtoken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TreeMap;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationFailedException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.ProfileID;
import org.ejbca.config.Configuration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.hardtoken.HardTokenProfileExistsException;
import org.ejbca.core.model.hardtoken.UnavailableTokenException;
import org.ejbca.core.model.hardtoken.profiles.EIDProfile;
import org.ejbca.core.model.hardtoken.profiles.EnhancedEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.HardTokenProfile;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.hardtoken.profiles.TurkishEIDProfile;
import org.ejbca.core.model.hardtoken.types.EIDHardToken;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.hardtoken.types.TurkishEIDHardToken;
import org.ejbca.core.model.ra.EndEntityManagementConstants;

/**
 * Stores data used by web server clients. Uses JNDI name for datasource as
 * defined in env 'Datasource' in ejb-jar.xml.
 * 
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "HardTokenSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class HardTokenSessionBean implements HardTokenSessionLocal, HardTokenSessionRemote {

    private static final Logger log = Logger.getLogger(EjbcaHardTokenBatchJobSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AccessControlSessionLocal authorizationSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private RoleAccessSessionLocal roleAccessSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;


    public static final int NO_ISSUER = 0;

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addHardTokenProfile(AuthenticationToken admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenProfile(name: " + name + ")");
        }
        addHardTokenProfile(admin, findFreeHardTokenProfileId(), name, profile);
        if (log.isTraceEnabled()) {
            log.trace("<addHardTokenProfile()");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addHardTokenProfile(AuthenticationToken admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenProfile(name: " + name + ", id: " + profileid + ")");
        }
        addHardTokenProfileInternal(admin, profileid, name, profile);
        final String msg = intres.getLocalizedMessage("hardtoken.addedprofile", name);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        if (log.isTraceEnabled()) {
            log.trace("<addHardTokenProfile()");
        }
    }

    private void addHardTokenProfileInternal(AuthenticationToken admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException, AuthorizationDeniedException {
        authorizedToEditProfile(admin);
        if (HardTokenProfileData.findByName(entityManager, name) == null && HardTokenProfileData.findByPK(entityManager, profileid) == null) {
            entityManager.persist(new HardTokenProfileData(profileid, name, profile));
        } else {
            final String msg = intres.getLocalizedMessage("hardtoken.erroraddprofile", name);
            log.info(msg);
            throw new HardTokenProfileExistsException();
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void changeHardTokenProfile(AuthenticationToken admin, String name, HardTokenProfile profile) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardTokenProfile(name: " + name + ")");
        }
        authorizedToEditProfile(admin);
        HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, name);
        if (htp != null) {
            // Make a diff what has changed
            final HardTokenProfile oldhtp = getHardTokenProfile(htp);
            final Map<Object, Object> diff = oldhtp.diff(profile);
            htp.setHardTokenProfile(profile);
            final String msg = intres.getLocalizedMessage("hardtoken.editedprofile", name);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(EjbcaEventTypes.HARDTOKEN_EDITPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        } else {
            final String msg = intres.getLocalizedMessage("hardtoken.erroreditprofile", name);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changeHardTokenProfile()");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void cloneHardTokenProfile(AuthenticationToken admin, String oldname, String newname) throws HardTokenProfileExistsException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">cloneHardTokenProfile(name: " + oldname + ")");
        }
        HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, oldname);
        try {
            HardTokenProfile profiledata = (HardTokenProfile) getHardTokenProfile(htp).clone();
            try {
                addHardTokenProfileInternal(admin, findFreeHardTokenProfileId(), newname, profiledata);
                final String msg = intres.getLocalizedMessage("hardtoken.clonedprofile", newname, oldname);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            } catch (HardTokenProfileExistsException f) {
                final String msg = intres.getLocalizedMessage("hardtoken.errorcloneprofile", newname, oldname);
                log.info(msg);
                throw f;
            }
        } catch (CloneNotSupportedException e) {
            throw new EJBException(e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<cloneHardTokenProfile()");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeHardTokenProfile(AuthenticationToken admin, String name) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenProfile(name: " + name + ")");
        }
        authorizedToEditProfile(admin);
        try {
            HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, name);
            if (htp == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove HardTokenProfileData that does not exist: "+name);                		
            	}
            } else {
            	entityManager.remove(htp);
                final String msg = intres.getLocalizedMessage("hardtoken.removedprofile", name);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVEPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("hardtoken.errorremoveprofile", name);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<removeHardTokenProfile()");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void renameHardTokenProfile(AuthenticationToken admin, String oldname, String newname) throws HardTokenProfileExistsException, AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">renameHardTokenProfile(from " + oldname + " to " + newname + ")");
        }
        boolean success = false;
        authorizedToEditProfile(admin);
        if (HardTokenProfileData.findByName(entityManager, newname) == null) {
            HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, oldname);
            if (htp != null) {
                htp.setName(newname);
                success = true;
            }
        }
        if (success) {
            final String msg = intres.getLocalizedMessage("hardtoken.renamedprofile", oldname, newname);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_EDITPROFILE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        } else {
            final String msg = intres.getLocalizedMessage("hardtoken.errorrenameprofile", oldname, newname);
            log.info(msg);
            throw new HardTokenProfileExistsException();
        }
        if (log.isTraceEnabled()) {
            log.trace("<renameHardTokenProfile()");
        }
        
    }

    @Override
    public Collection<Integer> getAuthorizedHardTokenProfileIds(AuthenticationToken admin) {
        ArrayList<Integer> returnval = new ArrayList<Integer>();
        HashSet<Integer> authorizedcertprofiles = new HashSet<Integer>(certificateProfileSession.getAuthorizedCertificateProfileIds(admin, CertificateConstants.CERTTYPE_HARDTOKEN));
        // It should be possible to indicate that a certificate should not be generated by not specifying a cert profile for this key. 
        authorizedcertprofiles.add(Integer.valueOf(CertificateProfileConstants.CERTPROFILE_NO_PROFILE));
        HashSet<Integer> authorizedcaids = new HashSet<Integer>(caSession.getAuthorizedCAs(admin));
        Collection<HardTokenProfileData> result = HardTokenProfileData.findAll(entityManager);
        Iterator<HardTokenProfileData> i = result.iterator();
        while (i.hasNext()) {
            HardTokenProfileData next = i.next();
            HardTokenProfile profile = getHardTokenProfile(next);
            if (profile instanceof EIDProfile) {
                if (authorizedcertprofiles.containsAll(((EIDProfile) profile).getAllCertificateProfileIds())
                        && authorizedcaids.containsAll(((EIDProfile) profile).getAllCAIds())) {
                    returnval.add(next.getId());
                }
            } else {
                // Implement for other profile types
            }
        }
        return returnval;
    }

    private void authorizedToEditProfile(AuthenticationToken admin) throws AuthorizationDeniedException {
        // We need to check that admin also have rights to edit certificate profiles
        if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, null);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public HashMap<Integer, String> getHardTokenProfileIdToNameMap() {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        Collection<HardTokenProfileData> result = HardTokenProfileData.findAll(entityManager);
        Iterator<HardTokenProfileData> i = result.iterator();
        while (i.hasNext()) {
            HardTokenProfileData next = i.next();
            returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }

    @Override
    public HardTokenProfile getHardTokenProfile(String name) {
        HardTokenProfile returnval = null;
        HardTokenProfileData htpd = HardTokenProfileData.findByName(entityManager, name);
        if (htpd != null) {
            returnval = getHardTokenProfile(htpd);
        }
        return returnval;
    }

    @Override
    public HardTokenProfile getHardTokenProfile(int id) {
        HardTokenProfile returnval = null;
        HardTokenProfileData htpd = HardTokenProfileData.findByPK(entityManager, Integer.valueOf(id));
        if (htpd != null) {
            returnval = getHardTokenProfile(htpd);
        }
        return returnval;
    }

    @Override
    public int getHardTokenProfileUpdateCount(int hardtokenprofileid) {
        int returnval = 0;
        HardTokenProfileData htpd = HardTokenProfileData.findByPK(entityManager, Integer.valueOf(hardtokenprofileid));
        if (htpd != null) {
            returnval = htpd.getUpdateCounter();
        }
        return returnval;
    }

    @Override
    public int getHardTokenProfileId(String name) {
        int returnval = 0;
        HardTokenProfileData htpd = HardTokenProfileData.findByName(entityManager, name);
        if (htpd != null) {
            returnval = htpd.getId();
        }
        return returnval;
    }

    @Override
    public String getHardTokenProfileName(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenProfileName(id: " + id + ")");
        }
        String returnval = null;
        HardTokenProfileData htpd = HardTokenProfileData.findByPK(entityManager, Integer.valueOf(id));
        if (htpd != null) {
            returnval = htpd.getName();
        }
        log.trace("<getHardTokenProfileName()");
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean addHardTokenIssuer(AuthenticationToken admin, String alias, int admingroupid, HardTokenIssuer issuerdata) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenIssuer(alias: " + alias + ")");
        }
        boolean returnval = addhardTokenIssuerInternal(admin, alias, admingroupid, issuerdata);
        if (returnval) {
            String msg = intres.getLocalizedMessage("hardtoken.addedissuer", alias);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDISSUER, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        } else {
        	// Does not exist
            String msg = intres.getLocalizedMessage("hardtoken.erroraddissuer", alias);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDISSUER, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        }
        if (log.isTraceEnabled()) {
            log.trace("<addHardTokenIssuer()");
        }
        return returnval;
    }

    private boolean addhardTokenIssuerInternal(final AuthenticationToken admin, final String alias, final int admingroupid, final HardTokenIssuer issuerdata) throws AuthorizationDeniedException {
        boolean returnval = false;
        authorizedToEditIssuer(admin);
        if (org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias) == null) {
            entityManager.persist(new org.ejbca.core.ejb.hardtoken.HardTokenIssuerData(findFreeHardTokenIssuerId(), alias, admingroupid, issuerdata));
            returnval = true;
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean changeHardTokenIssuer(AuthenticationToken admin, String alias, HardTokenIssuer issuerdata) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardTokenIssuer(alias: " + alias + ")");
        }
        boolean returnvalue = false;
        authorizedToEditIssuer(admin);
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            final HardTokenIssuer oldissuer = htih.getHardTokenIssuer();
            final Map<Object, Object> diff = oldissuer.diff(issuerdata);
            htih.setHardTokenIssuer(issuerdata);
            String msg = intres.getLocalizedMessage("hardtoken.editedissuer", alias);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            for (Map.Entry<Object, Object> entry : diff.entrySet()) {
                details.put(entry.getKey().toString(), entry.getValue().toString());
            }
            auditSession.log(EjbcaEventTypes.HARDTOKEN_EDITISSUER, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            returnvalue = true;
        } else {
        	// Does not exist
            String msg = intres.getLocalizedMessage("hardtoken.erroreditissuer", alias);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<changeHardTokenIssuer()");
        }
        return returnvalue;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean cloneHardTokenIssuer(AuthenticationToken admin, String oldalias, String newalias, int admingroupid) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">cloneHardTokenIssuer(alias: " + oldalias + ")");
        }
        boolean returnval = false;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, oldalias);
        if (htih != null) {
            try {
            	HardTokenIssuer issuerdata = (HardTokenIssuer) htih.getHardTokenIssuer().clone();
                returnval = addhardTokenIssuerInternal(admin, newalias, admingroupid, issuerdata);
            } catch (CloneNotSupportedException e) {
            }
        }
        if (returnval) {
            String msg = intres.getLocalizedMessage("hardtoken.clonedissuer", newalias, oldalias);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDISSUER, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        } else {
        	// Does not exist
            String msg = intres.getLocalizedMessage("hardtoken.errorcloneissuer", newalias, oldalias);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<cloneHardTokenIssuer()");
        }
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeHardTokenIssuer(AuthenticationToken admin, String alias) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenIssuer(alias: " + alias + ")");
        }
        authorizedToEditIssuer(admin);
        try {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
            if (htih == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove HardTokenProfileData that does not exist: "+alias);                		
            	}
            } else {
            	entityManager.remove(htih);
            	String msg = intres.getLocalizedMessage("hardtoken.removedissuer", alias);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVEISSUER, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            }
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremoveissuer", alias);
            log.info(msg, e);
        }
        if (log.isTraceEnabled()) {
            log.trace("<removeHardTokenIssuer()");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public boolean renameHardTokenIssuer(AuthenticationToken admin, String oldalias, String newalias, int newadmingroupid) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">renameHardTokenIssuer(from " + oldalias + " to " + newalias + ")");
        }
        authorizedToEditIssuer(admin);
        boolean returnvalue = false;
        if (org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, newalias) == null) {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, oldalias);
            if (htih != null) {
                htih.setAlias(newalias);
                htih.setAdminGroupId(newadmingroupid);
                returnvalue = true;
            }
        }
        if (returnvalue) {
            String msg = intres.getLocalizedMessage("hardtoken.renameissuer", oldalias, newalias);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_EDITISSUER, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        } else {
        	// Does not exist
            String msg = intres.getLocalizedMessage("hardtoken.errorrenameissuer", oldalias, newalias);
            log.info(msg);
        }
        if (log.isTraceEnabled()) {
            log.trace("<renameHardTokenIssuer()");
        }
        return returnvalue;
    }

    @Override
    public boolean isAuthorizedToEditHardTokenIssuer(AuthenticationToken token, String alias) {
        TreeMap<String, HardTokenIssuerInformation>  authorizedIssuers = getHardTokenIssuers(token);
        return authorizationSession.isAuthorizedNoLogging(token, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS) && authorizedIssuers.containsKey(alias);
    }
    
    @Override
    public boolean isAuthorizedToHardTokenIssuer(AuthenticationToken admin, String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">isAuthorizedToHardTokenIssuer(" + alias + ")");
        }
        boolean returnval = false;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
     
        if (htih != null) {
            RoleData role = roleAccessSession.findRole(htih.getAdminGroupId());
            boolean adminInRole = false;
            if(role != null) {
                for (Entry<Integer, AccessUserAspectData> entry : role.getAccessUsers().entrySet()) {
                    try {
                        if (admin.matches(entry.getValue())) {
                            adminInRole = true;
                            break;
                        }
                    } catch (AuthenticationFailedException e) {
                        // If AuthenticationFailedException was thrown for this token, then the token
                        // was invalid to begin with. Fail nicely and return false;
                        log.info("AuthenticationFailedException when evaluating authentication token " + admin, e);
                        break;
                    }
                }
            }
            returnval = authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS) && adminInRole;
               
        }
        if (log.isTraceEnabled()) {
        	log.trace("<isAuthorizedToHardTokenIssuer(" + returnval + ")");
        }
        return returnval;
    }
    
    private void authorizedToEditIssuer(AuthenticationToken admin) throws AuthorizationDeniedException {
        // We need to check that admin also have rights to edit certificate profiles
        if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS)) {
            final String msg = intres.getLocalizedMessage("authorization.notuathorizedtoresource", AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, null);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public Collection<HardTokenIssuerInformation> getHardTokenIssuerDatas(AuthenticationToken admin) {
        log.trace(">getHardTokenIssuerDatas()");
        ArrayList<HardTokenIssuerInformation> returnval = new ArrayList<HardTokenIssuerInformation>();
        Collection<Integer> authorizedhardtokenprofiles = getAuthorizedHardTokenProfileIds(admin);
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = i.next();
            if (authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
                returnval.add(new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
            }
        }
        Collections.sort(returnval);
        log.trace("<getHardTokenIssuerDatas()");
        return returnval;
    }

    @Override
    public Collection<String> getHardTokenIssuerAliases(AuthenticationToken admin) {
        log.trace(">getHardTokenIssuerAliases()");
        ArrayList<String> returnval = new ArrayList<String>();
        Collection<Integer> authorizedhardtokenprofiles = getAuthorizedHardTokenProfileIds(admin);
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = i.next();
            if (authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
                returnval.add(htih.getAlias());
            }
        }
        Collections.sort(returnval);
        log.trace("<getHardTokenIssuerAliases()");
        return returnval;
    }

    @Override
    public TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers(AuthenticationToken admin) {
        log.trace(">getHardTokenIssuers()");
        Collection<Integer> authorizedhardtokenprofiles = getAuthorizedHardTokenProfileIds(admin);
        TreeMap<String, HardTokenIssuerInformation> returnval = new TreeMap<String, HardTokenIssuerInformation>();
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = i.next();
            if (authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
                returnval.put(htih.getAlias(), new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih
                        .getHardTokenIssuer()));
            }
        }
        log.trace("<getHardTokenIssuers()");
        return returnval;
    }

    @Override
    public HardTokenIssuerInformation getHardTokenIssuerInformation(String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerData(alias: " + alias + ")");
        }
        HardTokenIssuerInformation returnval = null;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            returnval = new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
        log.trace("<getHardTokenIssuerData()");
        return returnval;
    }

    @Override
    public HardTokenIssuerInformation getHardTokenIssuerInformation(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerData(id: " + id + ")");
        }
        HardTokenIssuerInformation returnval = null;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
        if (htih != null) {
            returnval = new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
        log.trace("<getHardTokenIssuerData()");
        return returnval;
    }

    @Override
    public int getNumberOfHardTokenIssuers(AuthenticationToken admin) {
        log.trace(">getNumberOfHardTokenIssuers()");
        int returnval = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager).size();
        log.trace("<getNumberOfHardTokenIssuers()");
        return returnval;
    }

    @Override
    public int getHardTokenIssuerId(String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerId(alias: " + alias + ")");
        }
        int returnval = NO_ISSUER;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            returnval = htih.getId();
        }
        log.trace("<getHardTokenIssuerId()");
        return returnval;
    }

    @Override
    public String getHardTokenIssuerAlias(int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerAlias(id: " + id + ")");
        }
        String returnval = null;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
        if (htih != null) {
            returnval = htih.getAlias();
        }
        log.trace("<getHardTokenIssuerAlias()");
        return returnval;
    }

    /*
     * TODO: Somebody please clean the hell out of this method =) -mikek
     * 
     * getIs? srsly? and then toss an exception? orly?
     */
    @Override
    public void getIsHardTokenProfileAvailableToIssuer(int issuerid, EndEntityInformation userdata) throws UnavailableTokenException {
        if (log.isTraceEnabled()) {
            log.trace(">getIsTokenTypeAvailableToIssuer(issuerid: " + issuerid + ", tokentype: " + userdata.getTokenType() + ")");
        }
        boolean returnval = false;
        ArrayList<Integer> availabletokentypes = getHardTokenIssuerInformation(issuerid).getHardTokenIssuer().getAvailableHardTokenProfiles();
        for (int i = 0; i < availabletokentypes.size(); i++) {
            if (availabletokentypes.get(i).intValue() == userdata.getTokenType()) {
                returnval = true;
            }
        }
        if (!returnval) {
            String msg = intres.getLocalizedMessage("hardtoken.unavailabletoken", userdata.getUsername());
            throw new UnavailableTokenException(msg);
        }
        log.trace("<getIsTokenTypeAvailableToIssuer()");
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addHardToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn, int tokentype, HardToken hardtokendata,
            Collection<Certificate> certificates, String copyof) throws HardTokenExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardToken(tokensn : " + tokensn + ")");
        }
        final String bcdn = CertTools.stringToBCDNString(significantissuerdn);
        final org.ejbca.core.ejb.hardtoken.HardTokenData data = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
        if ( data!=null ) {
            String msg = intres.getLocalizedMessage("hardtoken.tokenexists", tokensn);
            log.info(msg);
            throw new HardTokenExistsException("Hard token with serial number '" + tokensn+ "' does exist.");
        }
        entityManager.persist(new org.ejbca.core.ejb.hardtoken.HardTokenData(tokensn, username, new java.util.Date(), new java.util.Date(),
                tokentype, bcdn, setHardToken(admin, ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID)).getHardTokenEncryptCA(),
                        hardtokendata)));
        if (certificates != null) {
            for ( Certificate cert : certificates ) {
                addHardTokenCertificateMapping(admin, tokensn, (X509Certificate)cert);
            }
        }
        if (copyof != null) {
            entityManager.persist(new HardTokenPropertyData(tokensn, HardTokenPropertyData.PROPERTY_COPYOF, copyof));
        }
        String msg = intres.getLocalizedMessage("hardtoken.addedtoken", tokensn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.HARDTOKEN_ADD, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, username, details);
        log.trace("<addHardToken()");
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void changeHardToken(AuthenticationToken admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardToken(tokensn : " + tokensn + ")");
        }
        final org.ejbca.core.ejb.hardtoken.HardTokenData htd = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
        if ( htd==null ) {
            String msg = intres.getLocalizedMessage("hardtoken.errorchangetoken", tokensn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            final String errorMessage = "Hard token with serial number '" + tokensn+ "' does not exist.";
            details.put("error", errorMessage);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_EDIT, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            throw new HardTokenDoesntExistsException(errorMessage);
        }
        htd.setTokenType(tokentype);
        htd.setData(setHardToken(admin, ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID)).getHardTokenEncryptCA(), hardtokendata));
        htd.setModifyTime(new java.util.Date());
        int caid = htd.getSignificantIssuerDN().hashCode();
        String msg = intres.getLocalizedMessage("hardtoken.changedtoken", tokensn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.HARDTOKEN_EDIT, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, htd.getUsername(), details);
        log.trace("<changeHardToken()");
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeHardToken(AuthenticationToken admin, String tokensn) throws HardTokenDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardToken(tokensn : " + tokensn + ")");
        }

        org.ejbca.core.ejb.hardtoken.HardTokenData htd = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
        if (htd == null) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremovetoken", tokensn);
            log.info(msg);
            throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
        }
        int caid = htd.getSignificantIssuerDN().hashCode();
        entityManager.remove(htd);
        // Remove all certificate mappings.
        removeHardTokenCertificateMappings(admin, tokensn);
        // Remove all copyof references id property database if they exist.
        HardTokenPropertyData htpd = HardTokenPropertyData.findByProperty(entityManager, tokensn, HardTokenPropertyData.PROPERTY_COPYOF);
        if (htpd != null) {
            entityManager.remove(htpd);
        }

        for (HardTokenPropertyData hardTokenPropertyData : HardTokenPropertyData.findIdsByPropertyAndValue(entityManager,
                HardTokenPropertyData.PROPERTY_COPYOF, tokensn)) {
            entityManager.remove(hardTokenPropertyData);
        }
        String msg = intres.getLocalizedMessage("hardtoken.removedtoken", tokensn);
        final Map<String, Object> details = new LinkedHashMap<String, Object>();
        details.put("msg", msg);
        auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, htd.getUsername(), details);
        log.trace("<removeHardToken()");
    }

    @Override
    public boolean existsHardToken(String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace(">existsHardToken(tokensn : " + tokensn + ")");
        }
        boolean ret = false;
        if (org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn) != null) {
            ret = true;
        }
        log.trace("<existsHardToken(): "+ret);
        return ret;
    }

    @Override
    public HardTokenInformation getHardToken(AuthenticationToken admin, String tokensn, boolean includePUK) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace(">getHardToken(tokensn :" + tokensn + ")");
        }
        HardTokenInformation returnval = null;
        org.ejbca.core.ejb.hardtoken.HardTokenData htd = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
        if (htd != null) {
            // Find Copyof
            String copyof = null;
            HardTokenPropertyData htpd = HardTokenPropertyData.findByProperty(entityManager, tokensn, HardTokenPropertyData.PROPERTY_COPYOF);
            if (htpd != null) {
                copyof = htpd.getValue();
            }
            ArrayList<String> copies = null;
            if (copyof == null) {
                // Find Copies
                Collection<HardTokenPropertyData> copieslocal = HardTokenPropertyData.findIdsByPropertyAndValue(entityManager,
                        HardTokenPropertyData.PROPERTY_COPYOF, tokensn);
                if (copieslocal.size() > 0) {
                    copies = new ArrayList<String>();
                    Iterator<HardTokenPropertyData> iter = copieslocal.iterator();
                    while (iter.hasNext()) {
                        copies.add(iter.next().getId());
                    }
                }
            }
            if (htd != null) {
                returnval = new HardTokenInformation(htd.getTokenSN(), htd.getUsername(), htd.getCreateTime(), htd.getModifyTime(), htd.getTokenType(), htd
                        .getSignificantIssuerDN(), getHardToken(admin, ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID)).getHardTokenEncryptCA(),
                        includePUK, htd.getData()), copyof, copies);
                int caid = htd.getSignificantIssuerDN().hashCode();
                String msg = intres.getLocalizedMessage("hardtoken.viewedtoken", tokensn);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_VIEWED, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, htd.getUsername(), details);
                if (includePUK) {
                    msg = intres.getLocalizedMessage("hardtoken.viewedpuk", tokensn);
                    final Map<String, Object> detailspuk = new LinkedHashMap<String, Object>();
                    detailspuk.put("msg", msg);
                    auditSession.log(EjbcaEventTypes.HARDTOKEN_VIEWEDPUK, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, htd.getUsername(), detailspuk);
                }
            }
        }
        log.trace("<getHardToken()");
        return returnval;
    }

    @Override
    public Collection<HardTokenInformation> getHardTokens(AuthenticationToken admin, String username, boolean includePUK) {
        if (log.isTraceEnabled()) {
            log.trace("<getHardToken(username :" + username + ")");
        }
        final ArrayList<HardTokenInformation> returnval = new ArrayList<HardTokenInformation>();
        final Collection<org.ejbca.core.ejb.hardtoken.HardTokenData> result = org.ejbca.core.ejb.hardtoken.HardTokenData.findByUsername(entityManager, username);
        for (org.ejbca.core.ejb.hardtoken.HardTokenData htd : result) {
            // Find Copyof
            String copyof = null;
            HardTokenPropertyData htpd = HardTokenPropertyData.findByProperty(entityManager, htd.getTokenSN(), HardTokenPropertyData.PROPERTY_COPYOF);
            if (htpd != null) {
                copyof = htpd.getValue();
            }
            ArrayList<String> copies = null;
            if (copyof == null) {
                // Find Copies
                Collection<HardTokenPropertyData> copieslocal = HardTokenPropertyData.findIdsByPropertyAndValue(entityManager,
                        HardTokenPropertyData.PROPERTY_COPYOF, htd.getTokenSN());
                if (copieslocal.size() > 0) {
                    copies = new ArrayList<String>();
                    Iterator<HardTokenPropertyData> iter = copieslocal.iterator();
                    while (iter.hasNext()) {
                        copies.add(iter.next().getId());
                    }
                }
            }
            returnval.add(new HardTokenInformation(htd.getTokenSN(), htd.getUsername(), htd.getCreateTime(), htd.getModifyTime(), htd.getTokenType(), htd
                    .getSignificantIssuerDN(), getHardToken(admin, ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(Configuration.GlobalConfigID)).getHardTokenEncryptCA(),
                    includePUK, htd.getData()), copyof, copies));
            int caid = htd.getSignificantIssuerDN().hashCode();
            String msg = intres.getLocalizedMessage("hardtoken.viewedtoken", htd.getTokenSN());
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_VIEWED, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, htd.getUsername(), details);
            if (includePUK) {
                msg = intres.getLocalizedMessage("hardtoken.viewedpuk", htd.getTokenSN());
                final Map<String, Object> detailspuk = new LinkedHashMap<String, Object>();
                detailspuk.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_VIEWEDPUK, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, htd.getUsername(), detailspuk);
            }
        }
        Collections.sort(returnval);
        log.trace("<getHardToken()");
        return returnval;
    }

    @Override
    public Collection<String> matchHardTokenByTokenSerialNumber(String searchpattern) {
        log.trace(">findHardTokenByTokenSerialNumber()");
        return org.ejbca.core.ejb.hardtoken.HardTokenData.findUsernamesByHardTokenSerialNumber(entityManager, searchpattern, EndEntityManagementConstants.MAXIMUM_QUERY_ROWCOUNT);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addHardTokenCertificateMapping(AuthenticationToken admin, String tokensn, Certificate certificate) {
        String certificatesn = CertTools.getSerialNumberAsString(certificate);
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenCertificateMapping(certificatesn : " + certificatesn + ", tokensn : " + tokensn + ")");
        }
        String fp = CertTools.getFingerprintAsString(certificate);
        if (HardTokenCertificateMap.findByCertificateFingerprint(entityManager, fp) == null) {
            try {
                entityManager.persist(new HardTokenCertificateMap(fp, tokensn));
                String msg = intres.getLocalizedMessage("hardtoken.addedtokencertmapping", certificatesn, tokensn);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDCERTMAP, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, certificatesn, null, details);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_ADDCERTMAP, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, certificatesn, null, details);
            }
        } else {
        	// Does not exist
            String msg = intres.getLocalizedMessage("hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
            log.info(msg);
        }
        log.trace("<addHardTokenCertificateMapping()");
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeHardTokenCertificateMapping(AuthenticationToken admin, Certificate certificate) {
        final String certificatesn = CertTools.getSerialNumberAsString(certificate);
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenCertificateMapping(Certificatesn: " + certificatesn + ")");
        }
        try {
            final HardTokenCertificateMap htcm = HardTokenCertificateMap.findByCertificateFingerprint(entityManager, CertTools.getFingerprintAsString(certificate));
            if (htcm == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove HardTokenCertificateMap that does not exist: "+CertTools.getFingerprintAsString(certificate));                		
            	}
            } else {
            	entityManager.remove(htcm);
            	final String msg = intres.getLocalizedMessage("hardtoken.removedtokencertmappingcert", certificatesn);
                final Map<String, Object> details = new LinkedHashMap<String, Object>();
                details.put("msg", msg);
                auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, certificatesn, null, details);
            }
        } catch (Exception e) {
            final String msg = intres.getLocalizedMessage("hardtoken.errorremovetokencertmappingcert", certificatesn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, certificatesn, null, details);
        }
        log.trace("<removeHardTokenCertificateMapping()");
    }

    /**
     * Removes all mappings between a hard token and a certificate.
     * 
     * @param admin the administrator calling the function
     * @param tokensn the serial number to remove.
     */
    private void removeHardTokenCertificateMappings(AuthenticationToken admin, String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenCertificateMappings(tokensn: " + tokensn + ")");
        }
        try {
            Iterator<HardTokenCertificateMap> result = HardTokenCertificateMap.findByTokenSN(entityManager, tokensn).iterator();
            while (result.hasNext()) {
                HardTokenCertificateMap htcm = result.next();
                entityManager.remove(htcm);
            }
            String msg = intres.getLocalizedMessage("hardtoken.removedtokencertmappingtoken", tokensn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremovetokencertmappingtoken", tokensn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_REMOVECERTMAP, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
        }
        log.trace("<removeHardTokenCertificateMappings()");
    }

    @Override
    public Collection<Certificate> findCertificatesInHardToken(String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesInHardToken(username :" + tokensn + ")");
        }
        ArrayList<Certificate> returnval = new ArrayList<Certificate>();
        try {
            Iterator<HardTokenCertificateMap> i = HardTokenCertificateMap.findByTokenSN(entityManager, tokensn).iterator();
            while (i.hasNext()) {
                HardTokenCertificateMap htcm = i.next();
                Certificate cert = certificateStoreSession.findCertificateByFingerprint(htcm.getCertificateFingerprint());
                if (cert != null) {
                    returnval.add(cert);
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        log.trace("<findCertificatesInHardToken()");
        return returnval;
    }

    @Override
    public String findHardTokenByCertificateSNIssuerDN(BigInteger certificatesn, String issuerdn) {
        if (log.isTraceEnabled()) {
            log.trace("<findHardTokenByCertificateSNIssuerDN(certificatesn :" + certificatesn + ", issuerdn :" + issuerdn + ")");
        }
        String returnval = null;
        X509Certificate cert = (X509Certificate) certificateStoreSession.findCertificateByIssuerAndSerno(issuerdn, certificatesn);
        if (cert != null) {
            HardTokenCertificateMap htcm = HardTokenCertificateMap.findByCertificateFingerprint(entityManager, CertTools.getFingerprintAsString(cert));
            if (htcm != null) {
                returnval = htcm.getTokenSN();
            }
        }
        log.trace("<findHardTokenByCertificateSNIssuerDN()");
        return returnval;
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void tokenGenerated(AuthenticationToken admin, String tokensn, String username, String significantissuerdn) {
        int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
        try {
            String msg = intres.getLocalizedMessage("hardtoken.generatedtoken", tokensn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_GENERATE, EventStatus.SUCCESS, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, username, details);
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void errorWhenGeneratingToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn) {
        int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
        try {
            String msg = intres.getLocalizedMessage("hardtoken.errorgeneratetoken", tokensn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_GENERATE, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), String.valueOf(caid), null, username, details);
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    @Override
    public List<String> getHardTokenProfileUsingCertificateProfile(int certificateProfileId) {
        List<String> result = new ArrayList<String>();
        Collection<Integer> certprofiles = null;
        HardTokenProfile profile = null;
        for(HardTokenProfileData profileData : HardTokenProfileData.findAll(entityManager)) {
            profile = getHardTokenProfile(profileData);
            if (profile instanceof EIDProfile) {
                certprofiles = ((EIDProfile) profile).getAllCertificateProfileIds();
                if (certprofiles.contains(certificateProfileId)) {
                    result.add(profileData.getName());
                }
            }
        }
        return result;
    }

    @Override
    public boolean existsHardTokenProfileInHardTokenIssuer(int id) {
        HardTokenIssuer issuer = null;
        Collection<Integer> hardtokenissuers = null;
        boolean exists = false;
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext() && !exists) {
            issuer = i.next().getHardTokenIssuer();
            hardtokenissuers = issuer.getAvailableHardTokenProfiles();
            if (hardtokenissuers.contains(Integer.valueOf(id))) {
                exists = true;
            }
        }
        return exists;
    }

    private int findFreeHardTokenProfileId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return HardTokenProfileData.findByPK(entityManager, Integer.valueOf(i))==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    private int findFreeHardTokenIssuerId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(i))==null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /** Method that returns the hard token data from a hashmap and updates it if necessary. */
    private HardToken getHardToken(AuthenticationToken admin, int encryptcaid, boolean includePUK, Map<?, ?> data) {
        HardToken returnval = null;

        if (data.get(org.ejbca.core.ejb.hardtoken.HardTokenData.ENCRYPTEDDATA) != null) {
            // Data in encrypted, decrypt
            byte[] encdata = (byte[]) data.get(org.ejbca.core.ejb.hardtoken.HardTokenData.ENCRYPTEDDATA);

            HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA, encdata);
            try {
                HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) caAdminSession.extendedService(admin, encryptcaid, request);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(response.getData()));
                data = (Map<?, ?>) ois.readObject();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }

        int tokentype = ((Integer) data.get(HardToken.TOKENTYPE)).intValue();

        switch (tokentype) {
        case SecConst.TOKEN_SWEDISHEID:
            returnval = new SwedishEIDHardToken(includePUK);
            break;
        case SecConst.TOKEN_ENHANCEDEID:
            returnval = new EnhancedEIDHardToken(includePUK);
            break;
        case SecConst.TOKEN_TURKISHEID:
            returnval = new TurkishEIDHardToken(includePUK);
            break;
        case SecConst.TOKEN_EID: // Left for backward compability
            returnval = new EIDHardToken(includePUK);
            break;
        default:
            returnval = new EIDHardToken(includePUK);
            break;
        }

        returnval.loadData(data);
        return returnval;
    }

    /**
     * Method that saves the hard token issuer data to a HashMap that can be
     * saved to database.
     */
	@SuppressWarnings("unchecked")
    private LinkedHashMap<String,byte[]> setHardToken(AuthenticationToken admin, int encryptcaid, HardToken tokendata) {
        LinkedHashMap<String,byte[]> retval = null;
        if (encryptcaid != 0) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream ois = new ObjectOutputStream(baos);
                ois.writeObject(tokendata.saveData());
                HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA, baos
                        .toByteArray());
                HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) caAdminSession.extendedService(admin, encryptcaid, request);
                LinkedHashMap<String,byte[]> data = new LinkedHashMap<String,byte[]>();
                data.put(org.ejbca.core.ejb.hardtoken.HardTokenData.ENCRYPTEDDATA, response.getData());
                retval = data;
            } catch (Exception e) {
                throw new EJBException(e);
            }
        } else {
            // Don't encrypt data
            retval = (LinkedHashMap<String,byte[]>) tokendata.saveData();
        }
        return retval;
    }

    private HardTokenProfile getHardTokenProfile(HardTokenProfileData htpData) {
        HardTokenProfile profile = null;
        java.beans.XMLDecoder decoder;
        try {
            decoder = new java.beans.XMLDecoder(new java.io.ByteArrayInputStream(htpData.getData().getBytes("UTF8")));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        final Map<?, ?> h = (Map<?, ?>) decoder.readObject();
        decoder.close();
        // Handle Base64 encoded string values
        final Map<?, ?> data = new Base64GetHashMap(h);
        switch (((Integer) (data.get(HardTokenProfile.TYPE))).intValue()) {
        case SwedishEIDProfile.TYPE_SWEDISHEID:
            profile = new SwedishEIDProfile();
            break;
        case EnhancedEIDProfile.TYPE_ENHANCEDEID:
            profile = new EnhancedEIDProfile();
            break;
        case TurkishEIDProfile.TYPE_TURKISHEID:
            profile = new TurkishEIDProfile();
            break;
        }
        profile.loadData(data);
        return profile;
    }
}
