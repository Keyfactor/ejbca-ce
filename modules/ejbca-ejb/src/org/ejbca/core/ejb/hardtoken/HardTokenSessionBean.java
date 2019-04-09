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
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.roles.Role;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.ProfileID;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.audit.enums.EjbcaEventTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaModuleTypes;
import org.ejbca.core.ejb.audit.enums.EjbcaServiceTypes;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceRequest;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.HardTokenEncryptCAServiceResponse;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.HardTokenInformation;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.HardTokenIssuerInformation;
import org.ejbca.core.model.hardtoken.types.EIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;

/**
 * HardToken API, this mimics "smart card" tokens where one token that has a serial number
 * may care multiple certificates. Different types of hard tokens have different profiles.
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
    private AuthorizationSessionLocal authorizationSession;
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
    private RoleSessionLocal roleSession;
    @EJB
    private SecurityEventsLoggerSessionLocal auditSession;

    public static final int NO_ISSUER = 0;
    

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
        if (HardTokenIssuerData.findByAlias(entityManager, alias) == null) {
            entityManager.persist(new HardTokenIssuerData(findFreeHardTokenIssuerId(), alias, admingroupid, issuerdata));
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
        HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, alias);
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
        HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, oldalias);
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
            HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, alias);
            if (htih == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove HardTokenIssuerData that does not exist: "+alias);
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
        if (HardTokenIssuerData.findByAlias(entityManager, newalias) == null) {
            HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, oldalias);
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
        HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, alias);
        if (htih != null) {
            if (authorizationSession.isAuthorizedNoLogging(admin, AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS)) {
                final List<Role> roles = roleSession.getRolesAuthenticationTokenIsMemberOf(admin);
                for (final Role role : roles) {
                    if (role.getRoleId()==htih.getAdminGroupId()) {
                        returnval = true;
                        break;
                    }
                }
            }
        }
        if (log.isTraceEnabled()) {
        	log.trace("<isAuthorizedToHardTokenIssuer(" + returnval + ")");
        }
        return returnval;
    }

    private void authorizedToEditIssuer(AuthenticationToken admin) throws AuthorizationDeniedException {
        // We need to check that admin also have rights to edit certificate profiles
        if (!authorizationSession.isAuthorized(admin, AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS)) {
            final String msg = intres.getLocalizedMessage("authorization.notauthorizedtoresource", AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, null);
            throw new AuthorizationDeniedException(msg);
        }
    }

    @Override
    public Collection<HardTokenIssuerInformation> getHardTokenIssuerDatas(AuthenticationToken admin) {
        log.trace(">getHardTokenIssuerDatas()");
        ArrayList<HardTokenIssuerInformation> returnval = new ArrayList<HardTokenIssuerInformation>();
        
        Collection<HardTokenIssuerData> result = HardTokenIssuerData.findAll(entityManager);
        Iterator<HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            HardTokenIssuerData htih = i.next();
            returnval.add(new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
            
        }
        Collections.sort(returnval);
        log.trace("<getHardTokenIssuerDatas()");
        return returnval;
    }

    @Override
    public Collection<String> getHardTokenIssuerAliases(AuthenticationToken admin) {
        log.trace(">getHardTokenIssuerAliases()");
        ArrayList<String> returnval = new ArrayList<String>();
        Collection<HardTokenIssuerData> result = HardTokenIssuerData.findAll(entityManager);
        Iterator<HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            HardTokenIssuerData htih = i.next();
            returnval.add(htih.getAlias());
        }
        Collections.sort(returnval);
        log.trace("<getHardTokenIssuerAliases()");
        return returnval;
    }

    @Override
    public TreeMap<String, HardTokenIssuerInformation> getHardTokenIssuers(AuthenticationToken admin) {
        log.trace(">getHardTokenIssuers()");
        TreeMap<String, HardTokenIssuerInformation> returnval = new TreeMap<String, HardTokenIssuerInformation>();
        Collection<HardTokenIssuerData> result = HardTokenIssuerData.findAll(entityManager);
        Iterator<HardTokenIssuerData> i = result.iterator();
        while (i.hasNext()) {
            HardTokenIssuerData htih = i.next();
            returnval.put(htih.getAlias(), new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer()));
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
        HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, alias);
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
        HardTokenIssuerData htih = HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
        if (htih != null) {
            returnval = new HardTokenIssuerInformation(htih.getId(), htih.getAlias(), htih.getAdminGroupId(), htih.getHardTokenIssuer());
        }
        log.trace("<getHardTokenIssuerData()");
        return returnval;
    }

    @Override
    public int getNumberOfHardTokenIssuers(AuthenticationToken admin) {
        log.trace(">getNumberOfHardTokenIssuers()");
        int returnval = HardTokenIssuerData.findAll(entityManager).size();
        log.trace("<getNumberOfHardTokenIssuers()");
        return returnval;
    }

    @Override
    public int getHardTokenIssuerId(String alias) {
        if (log.isTraceEnabled()) {
            log.trace(">getHardTokenIssuerId(alias: " + alias + ")");
        }
        int returnval = NO_ISSUER;
        HardTokenIssuerData htih = HardTokenIssuerData.findByAlias(entityManager, alias);
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
        if (id != 0) {
            HardTokenIssuerData htih = HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(id));
            if (htih != null) {
                returnval = htih.getAlias();
            }
        }
        log.trace("<getHardTokenIssuerAlias()");
        return returnval;
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addHardToken(AuthenticationToken admin, String tokensn, String username, String significantissuerdn, HardToken hardtokendata,
            Collection<Certificate> certificates, String copyof) throws HardTokenExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">addHardToken(tokensn : " + tokensn + ")");
        }
        final String bcdn = CertTools.stringToBCDNString(significantissuerdn);
        final HardTokenData data = HardTokenData.findByTokenSN(entityManager, tokensn);
        if ( data!=null ) {
            String msg = intres.getLocalizedMessage("hardtoken.tokenexists", tokensn);
            log.info(msg);
            throw new HardTokenExistsException("Hard token with serial number '" + tokensn+ "' does exist.");
        }
        entityManager.persist(new HardTokenData(tokensn, username, new java.util.Date(), new java.util.Date(),
                bcdn, setHardToken(admin, ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getHardTokenEncryptCA(),
                        hardtokendata)));
        if (certificates != null) {
            for ( Certificate cert : certificates ) {
                addHardTokenCertificateMapping(admin, tokensn, cert);
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
    public void changeHardToken(AuthenticationToken admin, String tokensn, HardToken hardtokendata) throws HardTokenDoesntExistsException {
        if (log.isTraceEnabled()) {
            log.trace(">changeHardToken(tokensn : " + tokensn + ")");
        }
        final HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokensn);
        if ( htd==null ) {
            String msg = intres.getLocalizedMessage("hardtoken.errorchangetoken", tokensn);
            final Map<String, Object> details = new LinkedHashMap<String, Object>();
            details.put("msg", msg);
            final String errorMessage = "Hard token with serial number '" + tokensn+ "' does not exist.";
            details.put("error", errorMessage);
            auditSession.log(EjbcaEventTypes.HARDTOKEN_EDIT, EventStatus.FAILURE, EjbcaModuleTypes.HARDTOKEN, EjbcaServiceTypes.EJBCA, admin.toString(), null, null, null, details);
            throw new HardTokenDoesntExistsException(errorMessage);
        }
        htd.setData(setHardToken(admin, ((GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getHardTokenEncryptCA(), hardtokendata));
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

        HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokensn);
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
        if (HardTokenData.findByTokenSN(entityManager, tokensn) != null) {
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
        HardTokenData htd = HardTokenData.findByTokenSN(entityManager, tokensn);
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
                GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
                HardToken hardToken = getHardToken(admin, globalConfiguration.getHardTokenEncryptCA(), includePUK, htd.getData());
                returnval = new HardTokenInformation(htd.getTokenSN(), htd.getUsername(), htd.getCreateTime(), htd.getModifyTime(), htd.getSignificantIssuerDN(), hardToken, copyof, copies);
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
        final Collection<HardTokenData> result = HardTokenData.findByUsername(entityManager, username);
        for (HardTokenData htd : result) {
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
            
            GlobalConfiguration globalConfiguration = (GlobalConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
            HardToken hardToken = getHardToken(admin, globalConfiguration.getHardTokenEncryptCA(), includePUK, htd.getData());
            returnval.add(new HardTokenInformation(htd.getTokenSN(), htd.getUsername(), htd.getCreateTime(), htd.getModifyTime(), htd.getSignificantIssuerDN(), 
                    hardToken, copyof, copies));
            
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
        GlobalCesecoreConfiguration globalConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
        return HardTokenData.findUsernamesByHardTokenSerialNumber(entityManager, searchpattern, globalConfiguration.getMaximumQueryCount());
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
    public Collection<Certificate> findCertificatesInHardToken(final String tokensn) {
        if (log.isTraceEnabled()) {
            log.trace("<findCertificatesInHardToken(tokensn :" + tokensn + ")");
        }
        final List<Certificate> ret = new ArrayList<Certificate>();
        for (final CertificateDataWrapper cdw : getCertificateDatasFromHardToken(tokensn)) {
            ret.add(cdw.getCertificate());
        }
        log.trace("<findCertificatesInHardToken()");
        return ret;
    }

    @Override
    public List<CertificateDataWrapper> getCertificateDatasFromHardToken(final String tokensn) {
        final List<CertificateDataWrapper> ret = new ArrayList<CertificateDataWrapper>();
        try {
            for (final HardTokenCertificateMap htcm : HardTokenCertificateMap.findByTokenSN(entityManager, tokensn)) {
                final CertificateDataWrapper cdw = certificateStoreSession.getCertificateData(htcm.getCertificateFingerprint());
                if (cdw != null) {
                    ret.add(cdw);
                }
            }
        } catch (Exception e) {
            throw new EJBException(e);
        }
        return ret;
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
    
    private int findFreeHardTokenIssuerId() {
        final ProfileID.DB db = new ProfileID.DB() {
            @Override
            public boolean isFree(int i) {
                return HardTokenIssuerData.findByPK(entityManager, Integer.valueOf(i)) == null;
            }
        };
        return ProfileID.getNotUsedID(db);
    }

    /** Method that returns the hard token data from a hashmap and updates it if necessary. */
    private HardToken getHardToken(AuthenticationToken admin, int encryptcaid, boolean includePUK, Map<?, ?> data) {
        HardToken returnval = null;

        if (data.get(HardTokenData.ENCRYPTEDDATA) != null) {
            // Data in encrypted, decrypt
            byte[] encdata = (byte[]) data.get(HardTokenData.ENCRYPTEDDATA);

            HardTokenEncryptCAServiceRequest request = new HardTokenEncryptCAServiceRequest(HardTokenEncryptCAServiceRequest.COMMAND_DECRYPTDATA, encdata);
            try {
                HardTokenEncryptCAServiceResponse response = (HardTokenEncryptCAServiceResponse) caAdminSession.extendedService(admin, encryptcaid, request);
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(response.getData()));
                data = (Map<?, ?>) ois.readObject();
            } catch (Exception e) {
                throw new EJBException(e);
            }
        }
        
        returnval = new EIDHardToken(includePUK);
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
                data.put(HardTokenData.ENCRYPTEDDATA, response.getData());
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
}
