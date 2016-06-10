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
package org.ejbca.ra;

import java.util.Map;
import java.util.TimeZone;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.ValidityDate;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;

/** 
 * UI representation of a result set item from the back end.
 * 
 * @version $Id$
 */
public class RaEndEntityDetails {

    public interface Callbacks {
        RaLocaleBean getRaLocaleBean();
        EndEntityProfile getEndEntityProfile(final int eepId);
    }

    private final Callbacks callbacks;

    private final String username;
    private final EndEntityInformation endEntityInformation;
    private final String subjectDn;
    private final String subjectAn;
    private final int eepId;
    private final String eepName;
    private final int cpId;
    private final String cpName;
    private final String caName;
    private final String created;
    private final String modified;
    private final int status;
    
    private EndEntityProfile endEntityProfile = null;
    private SubjectDn subjectDistinguishedName = null;
    private SubjectAlternativeName subjectAlternativeName = null;
    private SubjectDirectoryAttributes subjectDirectoryAttributes = null;

    private int styleRowCallCounter = 0;

    private RaEndEntityDetails next = null;
    private RaEndEntityDetails previous = null;

    public RaEndEntityDetails(final EndEntityInformation endEntity, final Callbacks callbacks,
            final Map<Integer, String> cpIdToNameMap, final Map<Integer, String> eepIdToNameMap, final Map<Integer,String> caIdToNameMap) {
        this.endEntityInformation = endEntity;
        this.callbacks = callbacks;
        this.username = endEntity.getUsername();
        this.subjectDn = endEntity.getDN();
        this.subjectAn = endEntity.getSubjectAltName();
        this.cpId = endEntity.getCertificateProfileId();
        this.cpName = cpIdToNameMap.get(Integer.valueOf(cpId));
        this.eepId = endEntity.getEndEntityProfileId();
        this.eepName = String.valueOf(eepIdToNameMap.get(Integer.valueOf(eepId)));
        this.caName = String.valueOf(caIdToNameMap.get(Integer.valueOf(endEntity.getCAId())));
        this.created = ValidityDate.formatAsISO8601ServerTZ(endEntity.getTimeCreated().getTime(), TimeZone.getDefault());
        this.modified = ValidityDate.formatAsISO8601ServerTZ(endEntity.getTimeModified().getTime(), TimeZone.getDefault());
        this.status = endEntity.getStatus();
    }
    public String getUsername() { return username; }
    public String getSubjectDn() { return subjectDn; }
    public String getSubjectAn() { return subjectAn; }
    public String getCaName() { return caName; }
    public String getCpName() {
        if (cpId==EndEntityInformation.NO_CERTIFICATEPROFILE) {
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_info_unknowncp");
        } else if (cpName!=null) {
            return cpName;
        }
        return callbacks.getRaLocaleBean().getMessage("search_ees_page_info_missingcp", cpId);
    }
    public boolean isCpNameSameAsEepName() { return getEepName().equals(getCpName()); }
    public String getEepName() {
        if (eepId==EndEntityInformation.NO_ENDENTITYPROFILE) {
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_info_unknowneep", eepId);
        } else if (eepName!=null) {
            return eepName;
        }
        return callbacks.getRaLocaleBean().getMessage("search_ees_page_info_missingeep", eepId);
    }
    public String getCreated() { return created; }
    public String getModified() { return modified; }
    public String getStatus() {
        switch (status) {
        case EndEntityConstants.STATUS_FAILED:
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_status_failed");
        case EndEntityConstants.STATUS_GENERATED:
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_status_generated");
        case EndEntityConstants.STATUS_KEYRECOVERY:
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_status_keyrecovery");
        case EndEntityConstants.STATUS_NEW:
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_status_new");
        case EndEntityConstants.STATUS_REVOKED:
            return callbacks.getRaLocaleBean().getMessage("search_ees_page_status_revoked");
        }
        return callbacks.getRaLocaleBean().getMessage("search_ees_page_status_other");
    }

    public SubjectDn getSubjectDistinguishedName() {
        if (subjectDistinguishedName==null) {
            this.subjectDistinguishedName = new SubjectDn(getEndEntityProfile(), endEntityInformation.getDN());
        }
        return subjectDistinguishedName;
    }

    public SubjectAlternativeName getSubjectAlternativeName() {
        if (subjectAlternativeName==null) {
            this.subjectAlternativeName = new SubjectAlternativeName(getEndEntityProfile(), endEntityInformation.getSubjectAltName());
        }
        return subjectAlternativeName;
        
    }

    public SubjectDirectoryAttributes getSubjectDirectoryAttributes() {
        if (subjectDirectoryAttributes==null) {
            String value = endEntityInformation.getExtendedinformation() == null ? null : endEntityInformation.getExtendedinformation().getSubjectDirectoryAttributes();
            this.subjectDirectoryAttributes = new SubjectDirectoryAttributes(getEndEntityProfile(), value);
        }
        return subjectDirectoryAttributes;
        
    }

    private EndEntityProfile getEndEntityProfile() {
        if (endEntityProfile==null) {
            endEntityProfile = callbacks.getEndEntityProfile(eepId);
        }
        return endEntityProfile;
    }
    
    /** @return true every twice starting with every forth call */
    public boolean isEven() {
        styleRowCallCounter++;
        return (styleRowCallCounter+1) / 2 % 2 == 0;
    }

    public RaEndEntityDetails getNext() { return next; }
    public void setNext(RaEndEntityDetails next) { this.next = next; }

    public RaEndEntityDetails getPrevious() { return previous; }
    public void setPrevious(RaEndEntityDetails previous) { this.previous = previous; }
}
