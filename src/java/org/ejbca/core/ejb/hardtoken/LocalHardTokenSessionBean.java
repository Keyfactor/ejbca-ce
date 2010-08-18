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

package org.ejbca.core.ejb.hardtoken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Random;
import java.util.TreeMap;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.JNDINames;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerData;
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
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.UserAdminConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.Base64GetHashMap;
import org.ejbca.util.CertTools;
import org.ejbca.util.JDBCUtil;

/**
 * Stores data used by web server clients. Uses JNDI name for datasource as
 * defined in env 'Datasource' in ejb-jar.xml.
 * 
 * @ejb.bean description="Session bean handling hard token data, both about hard tokens and hard token issuers."
 *           display-name="HardTokenSessionSB" name="HardTokenSession"
 *           jndi-name="HardTokenSession"
 *           local-jndi-name="HardTokenSessionLocal" view-type="both"
 *           type="Stateless" transaction-type="Container"
 * 
 * @ejb.transaction type="Supports"
 * 
 * @weblogic.enable-call-by-reference True
 * 
 * @ejb.env-entry description="The JDBC datasource to be used" name="DataSource"
 *                type="java.lang.String"
 *                value="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 * 
 * @ejb.home extends="javax.ejb.EJBHome" local-extends="javax.ejb.EJBLocalHome"
 *           local
 *           -class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome"
 *           remote-class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome"
 * 
 * @ejb.interface extends="javax.ejb.EJBObject"
 *                local-extends="javax.ejb.EJBLocalObject"
 *                local-class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal"
 *                remote
 *                -class="org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote"
 * 
 * @ejb.ejb-external-ref description="The hard token profile data entity bean"
 *                       view-type="local"
 *                       ref-name="ejb/HardTokenProfileDataLocal" type="Entity"
 *                       home=
 *                       "org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.hardtoken.HardTokenProfileDataLocal"
 *                       link="HardTokenProfileData"
 * 
 * @ejb.ejb-external-ref description="The hard token issuers data entity bean"
 *                       view-type="local"
 *                       ref-name="ejb/HardTokenIssuerDataLocal" type="Entity"
 *                       home=
 *                       "org.ejbca.core.ejb.hardtoken.HardTokenIssuerDataLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.hardtoken.HardTokenIssuerDataLocal"
 *                       link="HardTokenIssuerData"
 * 
 * @ejb.ejb-external-ref description="The hard token data entity bean"
 *                       view-type="local" ref-name="ejb/HardTokenDataLocal"
 *                       type="Entity"
 *                       home="org.ejbca.core.ejb.hardtoken.HardTokenDataLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.hardtoken.HardTokenDataLocal"
 *                       link="HardTokenData"
 * 
 * @ejb.ejb-external-ref description="The hard token property data entity bean"
 *                       view-type="local"
 *                       ref-name="ejb/HardTokenPropertyDataLocal" type="Entity"
 *                       home=
 *                       "org.ejbca.core.ejb.hardtoken.HardTokenPropertyLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.hardtoken.HardTokenPropertyLocal"
 *                       link="HardTokenPropertyData"
 * 
 * @ejb.ejb-external-ref 
 *                       description="The hard token to certificate map data entity bean"
 *                       view-type="local"
 *                       ref-name="ejb/HardTokenCertificateMapLocal"
 *                       type="Entity"
 *                       home="org.ejbca.core.ejb.hardtoken.HardTokenCertificateMapLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.hardtoken.HardTokenCertificateMapLocal"
 *                       link="HardTokenCertificateMap"
 * 
 * @ejb.ejb-external-ref description="The Authorization session bean"
 *                       view-type="local"
 *                       ref-name="ejb/AuthorizationSessionLocal" type="Session"
 *                       home=
 *                       "org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *                       link="AuthorizationSession"
 * 
 * @ejb.ejb-external-ref description="The CAAdmin Session Bean"
 *                       view-type="local" ref-name="ejb/CAAdminSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *                       link="CAAdminSession"
 * 
 * @ejb.ejb-external-ref description="The Certificate Store session bean"
 *                       view-type="local"
 *                       ref-name="ejb/CertificateStoreSessionLocal"
 *                       type="Session"
 *                       home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *                       business=
 *                       "org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *                       link="CertificateStoreSession"
 * 
 * @ejb.ejb-external-ref description="The Sign Session Bean" view-type="local"
 *                       ref-name="ejb/RSASignSessionLocal" type="Session"
 *                       home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *                       business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *                       link="RSASignSession"
 * 
 * @ejb.ejb-external-ref description="The RA Session Bean" view-type="local"
 *                       ref-name="ejb/RaAdminSessionLocal" type="Session"
 *                       home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *                       business
 *                       ="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *                       link="RaAdminSession"
 * 
 * @ejb.ejb-external-ref description="The log session bean" view-type="local"
 *                       ref-name="ejb/LogSessionLocal" type="Session"
 *                       home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *                       business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *                       link="LogSession"
 * 
 * @jonas.bean ejb-name="HardTokenSession"
 * 
 * @version $Id: LocalHardTokenSessionBean.java 9666 2010-08-18 11:22:12Z
 *          mikekushner $
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "HardTokenSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class LocalHardTokenSessionBean implements HardTokenSessionLocal, HardTokenSessionRemote {

    private static final Logger log = Logger.getLogger(LocalEjbcaHardTokenBatchJobSessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    @PersistenceContext(unitName = "ejbca")
    private EntityManager entityManager;

    @EJB
    private AuthorizationSessionLocal authorizationSession;
    @EJB
    private CertificateStoreSessionLocal certificateStoreSession;
    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private RaAdminSessionLocal raAdminSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private LogSessionLocal logSession;

    private static final String ENCRYPTEDDATA = "ENCRYPTEDDATA";
    public static final int NO_ISSUER = 0;

    /**
     * Adds a hard token profile to the database.
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addHardTokenProfile(Admin admin, String name, HardTokenProfile profile) throws HardTokenProfileExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenProfile(name: " + name + ")");
        }
        addHardTokenProfile(admin, findFreeHardTokenProfileId().intValue(), name, profile);
        log.trace("<addHardTokenProfile()");
    }

    /**
     * Adds a hard token profile to the database. Used for importing and
     * exporting profiles from xml-files.
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addHardTokenProfile(Admin admin, int profileid, String name, HardTokenProfile profile) throws HardTokenProfileExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenProfile(name: " + name + ", id: " + profileid + ")");
        }

        if (HardTokenProfileData.findByName(entityManager, name) == null && HardTokenProfileData.findByPK(entityManager, profileid) == null) {
            entityManager.persist(new HardTokenProfileData(profileid, name, profile));
            String msg = intres.getLocalizedMessage("hardtoken.addedprofile", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.erroraddprofile", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
            throw new HardTokenProfileExistsException();
        }
        log.trace("<addHardTokenProfile()");
    }

    /**
     * Updates hard token profile data
     * 
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeHardTokenProfile(Admin admin, String name, HardTokenProfile profile) {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardTokenProfile(name: " + name + ")");
        }
        HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, name);
        if (htp != null) {
            htp.setHardTokenProfile(profile);
            String msg = intres.getLocalizedMessage("hardtoken.editedprofile", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.erroreditprofile", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
        }
        log.trace("<changeHardTokenProfile()");
    }

    /**
     * Adds a hard token profile with the same content as the original profile,
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void cloneHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">cloneHardTokenProfile(name: " + oldname + ")");
        }
        HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, oldname);
        try {
            HardTokenProfile profiledata = (HardTokenProfile) getHardTokenProfile(htp).clone();
            try {
                addHardTokenProfile(admin, newname, profiledata);
                String msg = intres.getLocalizedMessage("hardtoken.clonedprofile", newname, oldname);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                        LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
            } catch (HardTokenProfileExistsException f) {
                String msg = intres.getLocalizedMessage("hardtoken.errorcloneprofile", newname, oldname);
                logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                        LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
                throw f;
            }
        } catch (CloneNotSupportedException e) {
            throw new EJBException(e);
        }
        log.trace("<cloneHardTokenProfile()");
    }

    /**
     * Removes a hard token profile from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeHardTokenProfile(Admin admin, String name) {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenProfile(name: " + name + ")");
        }
        try {
            HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, name);
            entityManager.remove(htp);
            String msg = intres.getLocalizedMessage("hardtoken.removedprofile", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremoveprofile", name);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg, e);
        }
        log.trace("<removeHardTokenProfile()");
    }

    /**
     * Renames a hard token profile
     * 
     * @throws HardTokenProfileExistsException
     *             if hard token already exists.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void renameHardTokenProfile(Admin admin, String oldname, String newname) throws HardTokenProfileExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">renameHardTokenProfile(from " + oldname + " to " + newname + ")");
        }
        boolean success = false;
        if (HardTokenProfileData.findByName(entityManager, newname) == null) {
            HardTokenProfileData htp = HardTokenProfileData.findByName(entityManager, oldname);
            if (htp != null) {
                htp.setName(newname);
                success = true;
            }
        }
        if (success) {
            String msg = intres.getLocalizedMessage("hardtoken.renamedprofile", oldname, newname);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENPROFILEDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.errorrenameprofile", oldname, newname);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENPROFILEDATA, msg);
            throw new HardTokenProfileExistsException();
        }
        log.trace("<renameHardTokenProfile()");
    }

    /**
     * Retrives a Collection of id:s (Integer) to authorized profiles.
     * 
     * Authorized hard token profiles are profiles containing only authorized
     * certificate profiles and caids.
     * 
     * @return Collection of id:s (Integer)
     * @ejb.interface-method view-type="both"
     */
    public Collection getAuthorizedHardTokenProfileIds(Admin admin) {
        ArrayList<Integer> returnval = new ArrayList<Integer>();
        HashSet<Integer> authorizedcertprofiles = new HashSet<Integer>(certificateStoreSession.getAuthorizedCertificateProfileIds(admin,
                SecConst.CERTTYPE_HARDTOKEN, caAdminSession.getAvailableCAs(admin)));
        HashSet<Integer> authorizedcaids = new HashSet<Integer>(caAdminSession.getAvailableCAs(admin));
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

    /**
     * Method creating a hashmap mapping profile id (Integer) to profile name
     * (String).
     * 
     * @ejb.interface-method view-type="both"
     */
    public HashMap getHardTokenProfileIdToNameMap(Admin admin) {
        HashMap<Integer, String> returnval = new HashMap<Integer, String>();
        Collection<HardTokenProfileData> result = HardTokenProfileData.findAll(entityManager);
        Iterator<HardTokenProfileData> i = result.iterator();
        while (i.hasNext()) {
            HardTokenProfileData next = i.next();
            returnval.put(next.getId(), next.getName());
        }
        return returnval;
    }

    /**
     * Retrives a named hard token profile.
     * 
     * @ejb.interface-method view-type="both"
     */
    public HardTokenProfile getHardTokenProfile(Admin admin, String name) {
        HardTokenProfile returnval = null;
        HardTokenProfileData htpd = HardTokenProfileData.findByName(entityManager, name);
        if (htpd != null) {
            returnval = getHardTokenProfile(htpd);
        }
        return returnval;
    }

    /**
     * Finds a hard token profile by id.
     * 
     * @ejb.interface-method view-type="both"
     */
    public HardTokenProfile getHardTokenProfile(Admin admin, int id) {
        HardTokenProfile returnval = null;
        HardTokenProfileData htpd = HardTokenProfileData.findByPK(entityManager, Integer.valueOf(id));
        if (htpd != null) {
            returnval = getHardTokenProfile(htpd);
        }
        return returnval;
    }

    /**
     * Help method used by hard token profile proxys to indicate if it is time
     * to update it's profile data.
     * 
     * @ejb.interface-method view-type="both"
     */
    public int getHardTokenProfileUpdateCount(Admin admin, int hardtokenprofileid) {
        int returnval = 0;
        HardTokenProfileData htpd = HardTokenProfileData.findByPK(entityManager, Integer.valueOf(hardtokenprofileid));
        if (htpd != null) {
            returnval = htpd.getUpdateCounter();
        }
        return returnval;
    }

    /**
     * Returns a hard token profile id, given it's hard token profile name
     * 
     * @return the id or 0 if hardtokenprofile cannot be found.
     * @ejb.interface-method view-type="both"
     */
    public int getHardTokenProfileId(Admin admin, String name) {
        int returnval = 0;
        HardTokenProfileData htpd = HardTokenProfileData.findByName(entityManager, name);
        if (htpd != null) {
            returnval = htpd.getId();
        }
        return returnval;
    }

    /**
     * Returns a hard token profile name given its id.
     * 
     * @return the name or null if id doesn't exist
     * @ejb.interface-method view-type="both"
     */
    public String getHardTokenProfileName(Admin admin, int id) {
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

    /**
     * Adds a hard token issuer to the database.
     * 
     * @return false if hard token issuer already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean addHardTokenIssuer(Admin admin, String alias, int admingroupid, HardTokenIssuer issuerdata) {
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenIssuer(alias: " + alias + ")");
        }
        boolean returnval = false;
        if (org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias) == null) {
            try {
                entityManager.persist(new org.ejbca.core.ejb.hardtoken.HardTokenIssuerData(findFreeHardTokenIssuerId(), alias, admingroupid, issuerdata));
                returnval = true;
            } catch (Exception e) {
            }
        }
        if (returnval) {
            String msg = intres.getLocalizedMessage("hardtoken.addedissuer", alias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENISSUERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.erroraddissuer", alias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA, msg);
        }
        log.trace("<addHardTokenIssuer()");
        return returnval;
    }

    /**
     * Updates hard token issuer data
     * 
     * @return false if alias doesn't exists
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean changeHardTokenIssuer(Admin admin, String alias, HardTokenIssuer issuerdata) {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardTokenIssuer(alias: " + alias + ")");
        }
        boolean returnvalue = false;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            htih.setHardTokenIssuer(issuerdata);
            String msg = intres.getLocalizedMessage("hardtoken.editedissuer", alias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENISSUERDATA, msg);
            returnvalue = true;
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.erroreditissuer", alias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA, msg);
        }
        log.trace("<changeHardTokenIssuer()");
        return returnvalue;
    }

    /**
     * Adds a hard token issuer with the same content as the original issuer,
     * 
     * @return false if the new alias or certificatesn already exists.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean cloneHardTokenIssuer(Admin admin, String oldalias, String newalias, int admingroupid) {
        if (log.isTraceEnabled()) {
            log.trace(">cloneHardTokenIssuer(alias: " + oldalias + ")");
        }
        HardTokenIssuer issuerdata = null;
        boolean returnval = false;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, oldalias);
        if (htih != null) {
            try {
                issuerdata = (HardTokenIssuer) htih.getHardTokenIssuer().clone();
                returnval = addHardTokenIssuer(admin, newalias, admingroupid, issuerdata);
            } catch (CloneNotSupportedException e) {
            }
        }
        if (returnval) {
            String msg = intres.getLocalizedMessage("hardtoken.clonedissuer", newalias, oldalias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENISSUERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.errorcloneissuer", newalias, oldalias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA, msg);
        }
        log.trace("<cloneHardTokenIssuer()");
        return returnval;
    }

    /**
     * Removes a hard token issuer from the database.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeHardTokenIssuer(Admin admin, String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenIssuer(alias: " + alias + ")");
        }
        try {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
            entityManager.remove(htih);
            String msg = intres.getLocalizedMessage("hardtoken.removedissuer", alias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENISSUERDATA, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremoveissuer", alias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA, msg, e);
        }
        log.trace("<removeHardTokenIssuer()");
    }

    /**
     * Renames a hard token issuer
     * 
     * @return false if new alias or certificatesn already exists
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public boolean renameHardTokenIssuer(Admin admin, String oldalias, String newalias, int newadmingroupid) {
        if (log.isTraceEnabled()) {
            log.trace(">renameHardTokenIssuer(from " + oldalias + " to " + newalias + ")");
        }
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
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_INFO_HARDTOKENISSUERDATA, msg);
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.errorrenameissuer", oldalias, newalias);
            logSession.log(admin, admin.getCaId(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null,
                    LogConstants.EVENT_ERROR_HARDTOKENISSUERDATA, msg);
        }
        log.trace("<renameHardTokenIssuer()");
        return returnvalue;
    }

    /**
     * Method to check if an administrator is authorized to issue hard tokens
     * for the given alias.
     * 
     * @param admin
     *            administrator to check
     * @param alias
     *            alias of hardtoken issuer.
     * @return true if administrator is authorized to issue hardtoken with given
     *         alias.
     * @ejb.interface-method view-type="both"
     */
    public boolean getAuthorizedToHardTokenIssuer(Admin admin, String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">getAuthorizedToHardTokenIssuer(" + alias + ")");
        }
        boolean returnval = false;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            try {
                int admingroupid = htih.getAdminGroupId();
                returnval = authorizationSession.isAuthorizedNoLog(admin, "/hardtoken_functionality/issue_hardtokens");
                returnval = returnval && authorizationSession.existsAdministratorInGroup(admin, admingroupid);
            } catch (AuthorizationDeniedException ade) {
            }
        }
        log.trace("<getAuthorizedToHardTokenIssuer(" + returnval + ")");
        return returnval;
    }

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * 
     * @return A collection of available HardTokenIssuerData.
     * @ejb.interface-method view-type="both"
     */
    public Collection getHardTokenIssuerDatas(Admin admin) {
        log.trace(">getHardTokenIssuerDatas()");
        ArrayList<HardTokenIssuerData> returnval = new ArrayList<HardTokenIssuerData>();
        Collection<Integer> authorizedhardtokenprofiles = getAuthorizedHardTokenProfileIds(admin);
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = i.next();
            if (authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
                returnval.add(new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
            }
        }
        Collections.sort(returnval);
        log.trace("<getHardTokenIssuerDatas()");
        return returnval;
    }

    /**
     * Returns the available hard token issuer alliases authorized to the
     * administrator.
     * 
     * @return A collection of available hard token issuer aliases.
     * @ejb.interface-method view-type="both"
     */
    public Collection getHardTokenIssuerAliases(Admin admin) {
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

    /**
     * Returns the available hard token issuers authorized to the administrator.
     * 
     * @return A treemap of available hard token issuers.
     * @ejb.interface-method view-type="both"
     */
    public TreeMap getHardTokenIssuers(Admin admin) {
        log.trace(">getHardTokenIssuers()");
        Collection<Integer> authorizedhardtokenprofiles = getAuthorizedHardTokenProfileIds(admin);
        TreeMap<String, HardTokenIssuerData> returnval = new TreeMap<String, HardTokenIssuerData>();
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = i.next();
            if (authorizedhardtokenprofiles.containsAll(htih.getHardTokenIssuer().getAvailableHardTokenProfiles())) {
                returnval.put(htih.getAlias(), new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih
                        .getHardTokenIssuer()));
            }
        }
        log.trace("<getHardTokenIssuers()");
        return returnval;
    }

    /**
     * Returns the specified hard token issuer.
     * 
     * @return the hard token issuer data or null if hard token issuer doesn't
     *         exists.
     * @ejb.interface-method view-type="both"
     */
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerData(alias: " + alias + ")");
        }
        HardTokenIssuerData returnval = null;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            returnval = new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
        log.trace("<getHardTokenIssuerData()");
        return returnval;
    }

    /**
     * Returns the specified hard token issuer.
     * 
     * @return the hard token issuer data or null if hard token issuer doesn't
     *         exists.
     * @ejb.interface-method view-type="both"
     */
    public HardTokenIssuerData getHardTokenIssuerData(Admin admin, int id) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerData(id: " + id + ")");
        }
        HardTokenIssuerData returnval = null;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
        if (htih != null) {
            returnval = new HardTokenIssuerData(htih.getId().intValue(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
        log.trace("<getHardTokenIssuerData()");
        return returnval;
    }

    /**
     * Returns the number of available hard token issuer.
     * 
     * @return the number of available hard token issuer.
     * @ejb.interface-method view-type="both"
     */
    public int getNumberOfHardTokenIssuers(Admin admin) {
        log.trace(">getNumberOfHardTokenIssuers()");
        int returnval = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager).size();
        log.trace("<getNumberOfHardTokenIssuers()");
        return returnval;
    }

    /**
     * Returns a hard token issuer id given its alias.
     * 
     * @return id number of hard token issuer.
     * @ejb.interface-method view-type="both"
     */
    public int getHardTokenIssuerId(Admin admin, String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerId(alias: " + alias + ")");
        }
        int returnval = NO_ISSUER;
        org.ejbca.core.ejb.hardtoken.HardTokenIssuerData htih = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            returnval = htih.getId().intValue();
        }
        log.trace("<getHardTokenIssuerId()");
        return returnval;
    }

    /**
     * Returns a hard token issuer alias given its id.
     * 
     * @return the alias or null if id noesnt exists
     * @ejb.interface-method view-type="both"
     */
    public String getHardTokenIssuerAlias(Admin admin, int id) {
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

    /**
     * Checks if a hard token profile is among a hard tokens issuers available
     * token types.
     * 
     * @param admin
     *            the administrator calling the function
     * @param issuerid
     *            the id of the issuer to check.
     * @param userdata
     *            the data of user about to be generated
     * 
     * @throws UnavailableTokenException
     *             if users tokentype isn't among hard token issuers available
     *             tokentypes.
     * @ejb.interface-method view-type="both"
     */
    public void getIsHardTokenProfileAvailableToIssuer(Admin admin, int issuerid, UserDataVO userdata) throws UnavailableTokenException {
        if (log.isTraceEnabled()) {
            log.trace(">getIsTokenTypeAvailableToIssuer(issuerid: " + issuerid + ", tokentype: " + userdata.getTokenType() + ")");
        }
        boolean returnval = false;
        ArrayList<Integer> availabletokentypes = getHardTokenIssuerData(admin, issuerid).getHardTokenIssuer().getAvailableHardTokenProfiles();
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

    /**
     * Adds a hard token to the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @param username
     *            the user owning the token.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     * @param hardtokendata
     *            the hard token data
     * @param certificates
     *            a collection of certificates places in the hard token
     * @param copyof
     *            indicates if the newly created token is a copy of an existing
     *            token. Use null if token is an original
     * 
     * @throws HardTokenExistsException
     *             if tokensn already exists in databas.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addHardToken(Admin admin, String tokensn, String username, String significantissuerdn, int tokentype, HardToken hardtokendata,
            Collection certificates, String copyof) throws HardTokenExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardToken(tokensn : " + tokensn + ")");
        }
        String bcdn = CertTools.stringToBCDNString(significantissuerdn);
        org.ejbca.core.ejb.hardtoken.HardTokenData data = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
        if (data == null) {
            try {
                entityManager.persist(new org.ejbca.core.ejb.hardtoken.HardTokenData(admin, tokensn, username, new java.util.Date(), new java.util.Date(),
                        tokentype, bcdn, setHardToken(admin, signSession, raAdminSession.getCachedGlobalConfiguration(admin).getHardTokenEncryptCA(),
                                hardtokendata)));
                if (certificates != null) {
                    Iterator<X509Certificate> i = certificates.iterator();
                    while (i.hasNext()) {
                        addHardTokenCertificateMapping(admin, tokensn, i.next());
                    }
                }
                if (copyof != null) {
                    entityManager.persist(new HardTokenPropertyData(tokensn, HardTokenPropertyData.PROPERTY_COPYOF, copyof));
                }
                String msg = intres.getLocalizedMessage("hardtoken.addedtoken", tokensn);
                logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), username, null,
                        LogConstants.EVENT_INFO_HARDTOKENDATA, msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("hardtoken.tokenexists", tokensn);
                logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), username, null,
                        LogConstants.EVENT_ERROR_HARDTOKENDATA, msg);
                throw new HardTokenExistsException("Tokensn : " + tokensn);
            }
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.tokenexists", tokensn);
            logSession.log(admin, bcdn.hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_HARDTOKENDATA,
                    msg);
            throw new HardTokenExistsException("Tokensn : " + tokensn);
        }
        log.trace("<addHardToken()");
    }

    /**
     * changes a hard token data in the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @param hardtokendata
     *            the hard token data
     * 
     * @throws HardTokenDoesntExistsException
     *             if tokensn doesn't exists in databas.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void changeHardToken(Admin admin, String tokensn, int tokentype, HardToken hardtokendata) throws HardTokenDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardToken(tokensn : " + tokensn + ")");
        }
        int caid = LogConstants.INTERNALCAID;
        try {
            org.ejbca.core.ejb.hardtoken.HardTokenData htd = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
            if (htd == null) {
                throw new FinderException();
            }
            htd.setTokenType(tokentype);
            htd.setData(setHardToken(admin, signSession, raAdminSession.getCachedGlobalConfiguration(admin).getHardTokenEncryptCA(), hardtokendata));
            htd.setModifyTime(new java.util.Date());
            caid = htd.getSignificantIssuerDN().hashCode();
            String msg = intres.getLocalizedMessage("hardtoken.changedtoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), htd.getUsername(), null, LogConstants.EVENT_INFO_HARDTOKENDATA,
                    msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorchangetoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_HARDTOKENDATA, msg);
            throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
        }
        log.trace("<changeHardToken()");
    }

    /**
     * removes a hard token data from the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     * @throws HardTokenDoesntExistsException
     *             if tokensn doesn't exists in databas.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeHardToken(Admin admin, String tokensn) throws HardTokenDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardToken(tokensn : " + tokensn + ")");
        }
        int caid = LogConstants.INTERNALCAID;
        try {
            org.ejbca.core.ejb.hardtoken.HardTokenData htd = org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn);
            if (htd == null) {
                throw new FinderException();
            }
            caid = htd.getSignificantIssuerDN().hashCode();
            entityManager.remove(htd);
            // Remove all certificate mappings.
            removeHardTokenCertificateMappings(admin, tokensn);
            // Remove all copyof references id property database.
            HardTokenPropertyData htpd = HardTokenPropertyData.findByProperty(entityManager, tokensn, HardTokenPropertyData.PROPERTY_COPYOF);
            entityManager.remove(htpd);
            Collection<HardTokenPropertyData> copieslocal = HardTokenPropertyData.findIdsByPropertyAndValue(entityManager,
                    HardTokenPropertyData.PROPERTY_COPYOF, tokensn);
            Iterator<HardTokenPropertyData> iter = copieslocal.iterator();
            while (iter.hasNext()) {
                entityManager.remove(iter.next());
            }
            String msg = intres.getLocalizedMessage("hardtoken.removedtoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_INFO_HARDTOKENDATA, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremovetoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_HARDTOKENDATA, msg);
            throw new HardTokenDoesntExistsException("Tokensn : " + tokensn);
        }
        log.trace("<removeHardToken()");
    }

    /**
     * Checks if a hard token serialnumber exists in the database
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * 
     * @return true if it exists or false otherwise.
     * @ejb.interface-method view-type="both"
     */
    public boolean existsHardToken(Admin admin, String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace(">existsHardToken(tokensn : " + tokensn + ")");
        }
        boolean ret = false;
        if (org.ejbca.core.ejb.hardtoken.HardTokenData.findByTokenSN(entityManager, tokensn) != null) {
            ret = true;
        }
        log.trace("<existsHardToken()");
        return ret;
    }

    /**
     * returns hard token data for the specified tokensn
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * 
     * @return the hard token data or NULL if tokensn doesnt exists in database.
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     */
    public HardTokenData getHardToken(Admin admin, String tokensn, boolean includePUK) throws AuthorizationDeniedException {
        if (log.isTraceEnabled()) {
            log.trace("<getHardToken(tokensn :" + tokensn + ")");
        }
        HardTokenData returnval = null;
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
                returnval = new HardTokenData(htd.getTokenSN(), htd.getUsername(), htd.getCreateTime(), htd.getModifyTime(), htd.getTokenType(), htd
                        .getSignificantIssuerDN(), getHardToken(admin, signSession, raAdminSession.getCachedGlobalConfiguration(admin).getHardTokenEncryptCA(),
                        includePUK, htd.getData()), copyof, copies);
                String msg = intres.getLocalizedMessage("hardtoken.viewedtoken", tokensn);
                logSession.log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), htd.getUsername(), null,
                        LogConstants.EVENT_INFO_HARDTOKENVIEWED, msg);
                if (includePUK) {
                    msg = intres.getLocalizedMessage("hardtoken.viewedpuk", tokensn);
                    logSession.log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), htd.getUsername(),
                            null, LogConstants.EVENT_INFO_PUKVIEWED, msg);
                }
            }
        }
        log.trace("<getHardToken()");
        return returnval;
    }

    /**
     * returns hard token data for the specified user
     * 
     * @param admin
     *            the administrator calling the function
     * @param username
     *            The username owning the tokens.
     * 
     * @return a Collection of all hard token user data.
     * @ejb.interface-method view-type="both"
     */
    public Collection getHardTokens(Admin admin, String username, boolean includePUK) {
        if (log.isTraceEnabled()) {
            log.trace("<getHardToken(username :" + username + ")");
        }
        ArrayList<HardTokenData> returnval = new ArrayList<HardTokenData>();
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenData> result = org.ejbca.core.ejb.hardtoken.HardTokenData.findByUsername(entityManager, username);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenData> i = result.iterator();
        while (i.hasNext()) {
            org.ejbca.core.ejb.hardtoken.HardTokenData htd = i.next();
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
            returnval.add(new HardTokenData(htd.getTokenSN(), htd.getUsername(), htd.getCreateTime(), htd.getModifyTime(), htd.getTokenType(), htd
                    .getSignificantIssuerDN(), getHardToken(admin, signSession, raAdminSession.getCachedGlobalConfiguration(admin).getHardTokenEncryptCA(),
                    includePUK, htd.getData()), copyof, copies));
            String msg = intres.getLocalizedMessage("hardtoken.viewedtoken", htd.getTokenSN());
            logSession.log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), htd.getUsername(), null,
                    LogConstants.EVENT_INFO_HARDTOKENVIEWED, msg);
            if (includePUK) {
                msg = intres.getLocalizedMessage("hardtoken.viewedpuk", htd.getTokenSN());
                logSession.log(admin, htd.getSignificantIssuerDN().hashCode(), LogConstants.MODULE_HARDTOKEN, new java.util.Date(), htd.getUsername(), null,
                        LogConstants.EVENT_INFO_PUKVIEWED, msg);
            }
        }
        log.trace("<getHardToken()");
        return returnval;
    }

    /**
     * Method that searches the database for a tokensn. It returns all
     * hardtokens with a serialnumber that begins with the given searchpattern.
     * 
     * @param admin
     *            the administrator calling the function
     * @param searchpattern
     *            of begining of hard token sn
     * @return a Collection of username(String) matching the search string
     * @ejb.interface-method view-type="both"
     */
    public Collection findHardTokenByTokenSerialNumber(Admin admin, String searchpattern) {
        log.trace(">findHardTokenByTokenSerialNumber()");
        ArrayList<String> returnval = new ArrayList<String>();
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        try {
            // Construct SQL query.
            con = JDBCUtil.getDBConnection(JNDINames.DATASOURCE);
            ps = con.prepareStatement("select distinct username from HardTokenData where  tokenSN LIKE '%" + searchpattern + "%'");
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.
            while (rs.next() && returnval.size() <= UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT) {
                returnval.add(rs.getString(1));
            }
            log.trace("<findHardTokenByTokenSerialNumber()");
            return returnval;

        } catch (Exception e) {
            throw new EJBException(e);
        } finally {
            JDBCUtil.close(con, ps, rs);
        }
    }

    /**
     * Adds a mapping between a hard token and a certificate
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * @param certificate
     *            the certificate to map to.
     * 
     * @throws EJBException
     *             if a communication or other error occurs.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void addHardTokenCertificateMapping(Admin admin, String tokensn, Certificate certificate) {
        String certificatesn = CertTools.getSerialNumberAsString(certificate);
        if (log.isTraceEnabled()) {
            log.trace(">addHardTokenCertificateMapping(certificatesn : " + certificatesn + ", tokensn : " + tokensn + ")");
        }
        int caid = CertTools.getIssuerDN(certificate).hashCode();
        String fp = CertTools.getFingerprintAsString(certificate);
        if (HardTokenCertificateMap.findByCertificateFingerprint(entityManager, fp) == null) {
            try {
                entityManager.persist(new HardTokenCertificateMap(fp, tokensn));
                String msg = intres.getLocalizedMessage("hardtoken.addedtokencertmapping", certificatesn, tokensn);
                logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_INFO_HARDTOKENCERTIFICATEMAP,
                        msg);
            } catch (Exception e) {
                String msg = intres.getLocalizedMessage("hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
                logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP,
                        msg);
            }
        } else {
            String msg = intres.getLocalizedMessage("hardtoken.erroraddtokencertmapping", certificatesn, tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP, msg);
        }
        log.trace("<addHardTokenCertificateMapping()");
    }

    /**
     * Removes a mapping between a hard token and a certificate
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificate
     *            the certificate to map to.
     * 
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void removeHardTokenCertificateMapping(Admin admin, Certificate certificate) {
        String certificatesn = CertTools.getSerialNumberAsString(certificate);
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenCertificateMapping(Certificatesn: " + certificatesn + ")");
        }
        int caid = CertTools.getIssuerDN(certificate).hashCode();
        try {
            HardTokenCertificateMap htcm = HardTokenCertificateMap.findByCertificateFingerprint(entityManager, CertTools.getFingerprintAsString(certificate));
            entityManager.remove(htcm);
            String msg = intres.getLocalizedMessage("hardtoken.removedtokencertmappingcert", certificatesn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_INFO_HARDTOKENCERTIFICATEMAP, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremovetokencertmappingcert", certificatesn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP, msg);
        }
        log.trace("<removeHardTokenCertificateMapping()");
    }

    /**
     * Removes all mappings between a hard token and a certificate
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            the serial number to remove.
     */
    private void removeHardTokenCertificateMappings(Admin admin, String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace(">removeHardTokenCertificateMappings(tokensn: " + tokensn + ")");
        }
        int caid = admin.getCaId();
        try {
            Iterator<HardTokenCertificateMap> result = HardTokenCertificateMap.findByTokenSN(entityManager, tokensn).iterator();
            while (result.hasNext()) {
                HardTokenCertificateMap htcm = result.next();
                entityManager.remove(htcm);
            }
            String msg = intres.getLocalizedMessage("hardtoken.removedtokencertmappingtoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_INFO_HARDTOKENCERTIFICATEMAP, msg);
        } catch (Exception e) {
            String msg = intres.getLocalizedMessage("hardtoken.errorremovetokencertmappingtoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), null, null, LogConstants.EVENT_ERROR_HARDTOKENCERTIFICATEMAP, msg);
        }
        log.trace("<removeHardTokenCertificateMappings()");
    }

    /**
     * Returns all the X509Certificates places in a hard token.
     * 
     * @param admin
     *            the administrator calling the function
     * @param tokensn
     *            The serialnumber of token.
     * 
     * @return a collection of X509Certificates
     * @ejb.interface-method view-type="both"
     */
    public Collection findCertificatesInHardToken(Admin admin, String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesInHardToken(username :" + tokensn + ")");
        }
        ArrayList<Certificate> returnval = new ArrayList<Certificate>();
        try {
            Iterator<HardTokenCertificateMap> i = HardTokenCertificateMap.findByTokenSN(entityManager, tokensn).iterator();
            while (i.hasNext()) {
                HardTokenCertificateMap htcm = i.next();
                Certificate cert = certificateStoreSession.findCertificateByFingerprint(admin, htcm.getCertificateFingerprint());
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

    /**
     * Returns the tokensn that the have blongs to a given certificatesn and
     * tokensn.
     * 
     * @param admin
     *            the administrator calling the function
     * @param certificatesn
     *            The serialnumber of certificate.
     * @param issuerdn
     *            the issuerdn of the certificate.
     * 
     * @return the serialnumber or null if no tokensn could be found.
     * @ejb.interface-method view-type="both"
     */
    public String findHardTokenByCertificateSNIssuerDN(Admin admin, BigInteger certificatesn, String issuerdn) {
        if (log.isTraceEnabled()) {
            log.trace("<findHardTokenByCertificateSNIssuerDN(certificatesn :" + certificatesn + ", issuerdn :" + issuerdn + ")");
        }
        String returnval = null;
        X509Certificate cert = (X509Certificate) certificateStoreSession.findCertificateByIssuerAndSerno(admin, issuerdn, certificatesn);
        if (cert != null) {
            HardTokenCertificateMap htcm = HardTokenCertificateMap.findByCertificateFingerprint(entityManager, CertTools.getFingerprintAsString(cert));
            if (htcm != null) {
                returnval = htcm.getTokenSN();
            }
        }
        log.trace("<findHardTokenByCertificateSNIssuerDN()");
        return returnval;
    }

    /**
     * Method used to signal to the log that token was generated successfully.
     * 
     * @param admin
     *            administrator performing action
     * @param tokensn
     *            tokensn of token generated
     * @param username
     *            username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void tokenGenerated(Admin admin, String tokensn, String username, String significantissuerdn) {
        int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
        try {
            String msg = intres.getLocalizedMessage("hardtoken.generatedtoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), username, null, LogConstants.EVENT_INFO_HARDTOKENGENERATED, msg);
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Method used to signal to the log that error occured when generating
     * token.
     * 
     * @param admin
     *            administrator performing action
     * @param tokensn
     *            tokensn of token.
     * @param username
     *            username of user token was generated for.
     * @param significantissuerdn
     *            indicates which CA the hard token should belong to.
     * @ejb.interface-method view-type="both"
     * @ejb.transaction type="Required"
     */
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void errorWhenGeneratingToken(Admin admin, String tokensn, String username, String significantissuerdn) {
        int caid = CertTools.stringToBCDNString(significantissuerdn).hashCode();
        try {
            String msg = intres.getLocalizedMessage("hardtoken.errorgeneratetoken", tokensn);
            logSession.log(admin, caid, LogConstants.MODULE_HARDTOKEN, new java.util.Date(), username, null, LogConstants.EVENT_ERROR_HARDTOKENGENERATED, msg);
        } catch (Exception e) {
            throw new EJBException(e);
        }
    }

    /**
     * Method to check if a certificate profile exists in any of the hard token
     * profiles. Used to avoid desyncronization of certificate profile data.
     * 
     * @param id
     *            the certificateprofileid to search for.
     * @return true if certificateprofileid exists in any of the hard token
     *         profiles.
     * @ejb.interface-method view-type="both"
     */
    public boolean existsCertificateProfileInHardTokenProfiles(Admin admin, int id) {
        HardTokenProfile profile = null;
        Collection<Integer> certprofiles = null;
        boolean exists = false;
        Collection<HardTokenProfileData> result = HardTokenProfileData.findAll(entityManager);
        Iterator<HardTokenProfileData> i = result.iterator();
        while (i.hasNext() && !exists) {
            profile = getHardTokenProfile(i.next());
            if (profile instanceof EIDProfile) {
                certprofiles = ((EIDProfile) profile).getAllCertificateProfileIds();
                if (certprofiles.contains(new Integer(id))) {
                    exists = true;
                }
            }
        }
        return exists;
    }

    /**
     * Method to check if a hard token profile exists in any of the hard token
     * issuers. Used to avoid desyncronization of hard token profile data.
     * 
     * @param id
     *            the hard token profileid to search for.
     * @return true if hard token profileid exists in any of the hard token
     *         issuers.
     * @ejb.interface-method view-type="both"
     */
    public boolean existsHardTokenProfileInHardTokenIssuer(Admin admin, int id) {
        HardTokenIssuer issuer = null;
        Collection<Integer> hardtokenissuers = null;
        boolean exists = false;
        Collection<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> result = org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findAll(entityManager);
        Iterator<org.ejbca.core.ejb.hardtoken.HardTokenIssuerData> i = result.iterator();
        while (i.hasNext() && !exists) {
            issuer = i.next().getHardTokenIssuer();
            hardtokenissuers = issuer.getAvailableHardTokenProfiles();
            if (hardtokenissuers.contains(new Integer(id))) {
                exists = true;
            }
        }
        return exists;
    }

    private Integer findFreeHardTokenProfileId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
            if (id > SecConst.TOKEN_SOFT) {
                if (HardTokenProfileData.findByPK(entityManager, Integer.valueOf(id)) == null) {
                    foundfree = true;
                }
            }
            id = ran.nextInt();
        }
        return new Integer(id);
    }

    private Integer findFreeHardTokenIssuerId() {
        Random ran = (new Random((new Date()).getTime()));
        int id = ran.nextInt();
        boolean foundfree = false;
        while (!foundfree) {
            if (id > 1) {
                if (org.ejbca.core.ejb.hardtoken.HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id)) == null) {
                    foundfree = true;
                }
            }
            id = ran.nextInt();
        }
        return new Integer(id);
    }

    /**
     * Method that returns the hard token data from a hashmap and updates it if
     * nessesary.
     */
    private HardToken getHardToken(Admin admin, SignSessionLocal signsession, int encryptcaid, boolean includePUK, HashMap data) {
        HardToken returnval = null;

        if (data.get(ENCRYPTEDDATA) != null) {
            // Data in encrypted, decrypt
            byte[] encdata = (byte[]) data.get(ENCRYPTEDDATA);

            HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA, encdata);
            try {
                HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) caAdminSession.extendedService(admin, encryptcaid, request);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(response.getData()));
                data = (HashMap) ois.readObject();
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
    private HashMap setHardToken(Admin admin, SignSessionLocal signsession, int encryptcaid, HardToken tokendata) {
        HashMap retval = null;
        if (encryptcaid != 0) {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream ois = new ObjectOutputStream(baos);
                ois.writeObject(tokendata.saveData());
                HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_ENCRYPTDATA, baos
                        .toByteArray());
                HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) caAdminSession.extendedService(admin, encryptcaid, request);
                HashMap data = new HashMap();
                data.put(ENCRYPTEDDATA, response.getData());
                retval = data;
            } catch (Exception e) {
                new EJBException(e);
            }
        } else {
            // Don't encrypt data
            retval = (HashMap) tokendata.saveData();
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
        HashMap h = (HashMap) decoder.readObject();
        decoder.close();
        // Handle Base64 encoded string values
        HashMap data = new Base64GetHashMap(h);
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
