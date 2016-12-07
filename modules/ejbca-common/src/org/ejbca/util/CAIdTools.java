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
package org.ejbca.util;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.lang.StringUtils;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.ejbca.config.CmpConfiguration;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.model.ca.caadmin.extendedcaservices.CmsCAServiceInfo;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.BaseUserDataSource;
import org.ejbca.core.model.services.IWorker;
import org.ejbca.core.model.services.ServiceConfiguration;

/**
 * <p>Methods to update a changed CA Subject DN and CA Id in various objects.</p>
 * 
 * <p>The methods always take an object to change, as well as the old and new CA Ids and the new Subject DN.
 * They return true if the object was changed and should be updated in the database.</p>
 * 
 * <p>The reason for having the methods here and not in the respective objects is:</p>
 * <ol>
 * <li>Access rules are simply a list of access rule objects, so it can't have any methods directly on it anyway.</li>
 * <li>Some objects do not know about all of their properties. The ServiceConfiguration object
 * does not know about the different types of services it can store.</li>
 * <li>Some objects do not have a single base class, such as InternalKeyBindings which has two.</li>
 * </ol>
 * 
 * @version $Id$
 */
public final class CAIdTools {

    /** Static class. Can't be instantiated */ 
    private CAIdTools() { }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param certProfile Profile object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the certificate profile was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final CertificateProfile certProfile, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        final List<Integer> availableCAs = new ArrayList<>(certProfile.getAvailableCAs());
        // The list is modified so we can't use an iterator
        for (int i = 0; i < availableCAs.size(); i++) {
            int value = availableCAs.get(i);
            if (value == fromId) {
                availableCAs.set(i, toId);
                changed = true;
            }
        }
        if (changed) {
            certProfile.setAvailableCAs(availableCAs);
        }
        return changed;
    }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param endEntityProfile Profile object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the end entity profile was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final EndEntityProfile endEntityProfile, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        
        final Collection<String> original = endEntityProfile.getAvailableCAs();
        final List<Integer> updated = new ArrayList<>();
        for (String oldvalueStr : original) {
            int oldvalue = Integer.valueOf(oldvalueStr);
            int newvalue;
            if (oldvalue == fromId) {
                newvalue = toId;
                changed = true;
            } else {
                newvalue = oldvalue;
            }
            updated.add(newvalue);
        }
        
        if (changed) {
            endEntityProfile.setAvailableCAs(updated);
        }
        
        if (endEntityProfile.getDefaultCA() == fromId) {
            endEntityProfile.setValue(EndEntityProfile.DEFAULTCA, 0, String.valueOf(toId));
            changed = true;
        }
        
        return changed;
    }
    
    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param dataSource Data source object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the data source was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final BaseUserDataSource dataSource, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        final List<Integer> applicableCAs = new ArrayList<>(dataSource.getApplicableCAs());
        // The list is modified so we can't use an iterator
        for (int i = 0; i < applicableCAs.size(); i++) {
            int value = applicableCAs.get(i);
            if (value == fromId) {
                applicableCAs.set(i, toId);
                changed = true;
            }
        }
        if (changed) {
            dataSource.setApplicableCAs(applicableCAs);
        }
        return changed;
    }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param serviceConf Service object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the service was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final ServiceConfiguration serviceConf, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        final Properties workerProps = serviceConf.getWorkerProperties();
        final String idsToCheckStr = workerProps.getProperty(IWorker.PROP_CAIDSTOCHECK);
        if (!StringUtils.isEmpty(idsToCheckStr)) {
            final String[] caIds = idsToCheckStr.split(";");
            for (int i = 0; i < caIds.length; i++) {
                if (Integer.parseInt(caIds[i]) == fromId) {
                    caIds[i] = String.valueOf(toId);
                    changed = true;
                }
            }
            if (changed) {
                workerProps.setProperty(IWorker.PROP_CAIDSTOCHECK, StringUtils.join(caIds, ';'));
                serviceConf.setWorkerProperties(workerProps);
            }
        }
        return changed;
    }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param keybind Internal key binding object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the key binding was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final InternalKeyBinding keybind, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        List<InternalKeyBindingTrustEntry> trustentries = new ArrayList<>();
        for (InternalKeyBindingTrustEntry trustentry : keybind.getTrustedCertificateReferences()) {
            int trustCaId = trustentry.getCaId();
            if (trustCaId == fromId) {
                trustCaId = toId;
                changed = true;
            }
            trustentries.add(new InternalKeyBindingTrustEntry(trustCaId, trustentry.fetchCertificateSerialNumber()));
        }
        if (changed) {
            keybind.setTrustedCertificateReferences(trustentries);
        }
        return changed;
    }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param globalConfig Global configuration object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the configuration was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final GlobalConfiguration globalConfig, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        if (globalConfig.getAutoEnrollCA() == fromId) {
            globalConfig.setAutoEnrollCA(toId);
            changed = true;
        }
        return changed;
    }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param cmpConfig CMP configuration object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the configuration changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final CmpConfiguration cmpConfig, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        for (String alias : cmpConfig.getAliasList()) {
            final String defaultCaDN = cmpConfig.getCMPDefaultCA(alias);
            if (defaultCaDN != null && defaultCaDN.hashCode() == fromId) {
                cmpConfig.setCMPDefaultCA(alias, toSubjectDN);
                changed = true;
            }
        }
        return changed;
    }

    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param ocspConfig OCSP configuration object to modify.
     * @param fromId Old CA Id to replace.
     * @param toId New CA Id to replace with.
     * @param toSubjectDN New CA Subject DN.
     * @return True if the configuration was changed. If so it should be persisted to the database.
     */
    public static boolean updateCAIds(final GlobalOcspConfiguration ocspConfig, final int fromId, final int toId, final String toSubjectDN) {
        boolean changed = false;
        if (ocspConfig.getOcspDefaultResponderReference() != null &&
                ocspConfig.getOcspDefaultResponderReference().hashCode() == fromId) {
            ocspConfig.setOcspDefaultResponderReference(toSubjectDN);
            changed = true;
        }
        return changed;
    }
    
    /**
     * Updates any references to a CA's CAId and Subject DN.
     * @param roleName Name of the role. Used when creating roles to replace the old roles with.
     * @param rules Access rules of the role. Updated in place.
     * @param users Access users of the role. Updated in place.
     * @param fromId Old CA Id.
     * @param toId New CA Id.
     * @param toSubjectDN New CA Subject DN.
     * @return True if there was a change.
     */
    public static boolean updateCAIds(final String roleName, final Map<Integer,AccessRuleData> rules, final Map<Integer,AccessUserAspectData> users, final int fromId, final int toId, final String toSubjectDN) {
        final String toReplace = StandardRules.CAACCESS.resource()+String.valueOf(fromId);
        final String toReplaceSlash = toReplace+"/";
        boolean changed = false;
        // Look for references from access rules
        for (int id : new ArrayList<>(rules.keySet())) {
            AccessRuleData rule = rules.get(id);
            final String accessRuleName = rule.getAccessRuleName();
            
            if (accessRuleName.equals(toReplace) || accessRuleName.startsWith(toReplaceSlash)) {
                final String newName = StandardRules.CAACCESS.resource() + String.valueOf(toId) + accessRuleName.substring(toReplace.length());
                final int state = rule.getState();
                rule = new AccessRuleData(roleName, newName, rule.getInternalState(), rule.getRecursive());
                rule.setState(state);
                rules.put(id, rule);
                changed = true;
            }
        }
        // Look for references from access users
        for (int id : new ArrayList<>(users.keySet())) {
            AccessUserAspectData user = users.get(id);
            if (user.getCaId() == fromId) {
                user = new AccessUserAspectData(roleName, toId, user.getMatchWith(), user.getTokenType(), user.getMatchTypeAsType(), user.getMatchValue());
                users.put(id, user);
                changed = true;
            }
        }
        return changed;
    }
    
    /**
     * Rebuilds extended services so the Subject DN gets updated.
     */
    public static void rebuildExtendedServices(final CAInfo cainfo) {
        final List<ExtendedCAServiceInfo> extsvcs = new ArrayList<>();
        final String casubjdn = cainfo.getSubjectDN();
        for (ExtendedCAServiceInfo extsvc : cainfo.getExtendedCAServiceInfos()) {
            if (extsvc instanceof CmsCAServiceInfo) {
                final CmsCAServiceInfo cmssvc = (CmsCAServiceInfo) extsvc;
                extsvc = new CmsCAServiceInfo(extsvc.getStatus(), "CN=CMSCertificate, " + casubjdn, cmssvc.getSubjectAltName(), cmssvc.getKeySpec(), cmssvc.getKeyAlgorithm());
            }
            extsvcs.add(extsvc);
        }
        cainfo.setExtendedCAServiceInfos(extsvcs);
    }
}
