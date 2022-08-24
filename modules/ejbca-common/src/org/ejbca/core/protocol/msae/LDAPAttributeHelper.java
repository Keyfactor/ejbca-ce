/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.msae;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;

import org.apache.log4j.Logger;
import org.cesecore.config.MSAutoEnrollmentSettingsTemplate;
import org.cesecore.util.TimeUnitFormat;

import net.tirasa.adsddl.ntsd.ACE;
import net.tirasa.adsddl.ntsd.SDDL;
import net.tirasa.adsddl.ntsd.SID;
import net.tirasa.adsddl.ntsd.data.AceType;
import net.tirasa.adsddl.ntsd.data.AceRights.ObjectRight;
import net.tirasa.adsddl.ntsd.utils.GUID;

public class LDAPAttributeHelper {

    private static final Logger log = Logger.getLogger(LDAPAttributeHelper.class);
    
    // XCEP Enrollment Flags
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/cd22d3a0-f469-4a44-95ed-d10ce4dc2063
    private static final int CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS = 1;
    private static final int CT_FLAG_PUBLISH_TO_DS = 8;
    private static final int CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 16;
    private static final int CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 64;
    private static final int CT_FLAG_USER_INTERACTION_REQUIRED = 256;
    private static final int CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 1024;
    private static final int CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 8192;
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-winerrata/6898053e-8726-4209-ade2-37f8b0474c99
    private static final int CT_FLAG_NO_SECURITY_EXTENSION = 0x00080000;
    
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/1522b774-6464-41a3-87a5-1e5633c3fbbb
    private static final String AD_ACCESS_TYPE_ENROLL = "0e10c968-78fb-11d2-90d4-00c04f79dc55";
    private static final String AD_ACCESS_TYPE_AUTOENROLL = "a05b8cc2-17bc-4802-a710-e7c15ab866a2";
    
    // Certificate Template Name Flags
    // https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1
    private static final int CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS =  4194304;
    private static final int CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 16777216;
    private static final int CT_FLAG_SUBJECT_ALT_REQUIRE_UPN = 33554432;
    private static final int CT_FLAG_SUBJECT_ALT_REQUIRE_SPN = 8388608;
    private static final int CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 67108864;
    private static final int CT_FLAG_SUBJECT_ALT_REQUIRE_DNS = 134217728;
    private static final int CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN = 268435456;
    private static final int CT_FLAG_SUBJECT_REQUIRE_EMAIL = 536870912;
    private static final int CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME = 1073741824;
    private static final int CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH = -2147483648;

    public static MSAutoEnrollmentSettingsTemplate getMSAutoEnrollmentSettingTemplate(final javax.naming.directory.Attributes attributes) {
        final MSAutoEnrollmentSettingsTemplate msaeTemplate = new MSAutoEnrollmentSettingsTemplate();
        final String certificateNameFlag = getAttributeString(attributes, "msPKI-Certificate-Name-Flag");
        final String templateOid = getAttributeString(attributes, "msPKI-Cert-Template-OID");
        final String displayName = getAttributeString(attributes, "DisplayName");
        final String name = getAttributeString(attributes, "Name");
        final String templateMinorRevision = getAttributeString(attributes, "msPKI-Template-Minor-Revision");
        final String templateMajorRevision = getAttributeString(attributes, "revision");
        final String enrollmentFlag = getAttributeString(attributes, "msPKI-Enrollment-Flag");
        if (certificateNameFlag == null || templateOid == null || enrollmentFlag == null) {
            return null;
        }
        
        // Set Template OID
        msaeTemplate.setOid(templateOid);
        // Set Minor Revision
        msaeTemplate.setMinorRevision(templateMinorRevision);
        msaeTemplate.setMajorRevision(templateMajorRevision);
        // Set Display Name
        msaeTemplate.setDisplayName(displayName);
        // Set Name
        msaeTemplate.setName(name);
        // Set Publish To AD
        final Long adEnrollment = Long.valueOf(enrollmentFlag);
        msaeTemplate.setPublishToActiveDirectory((adEnrollment & CT_FLAG_PUBLISH_TO_DS) != 0);
        // if set, then skip adding security extension
        msaeTemplate.setExcludeObjectSidInNtdsSecurityExtension((adEnrollment & CT_FLAG_NO_SECURITY_EXTENSION) != 0);
        // Set Name Flags
        final Long nameFlag = Long.valueOf(certificateNameFlag);
        msaeTemplate.setIncludeNetBiosInSubjectSAN((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_DOMAIN_DNS) != 0);
        msaeTemplate.setIncludeDomainInSubjectSAN((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_DNS) != 0);
        msaeTemplate.setIncludeObjectGuidInSubjectSAN((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_DIRECTORY_GUID) != 0);
        msaeTemplate.setIncludeUPNInSubjectSAN((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN) != 0);
        msaeTemplate.setIncludeSPNInSubjectSAN((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_SPN) != 0);
        msaeTemplate.setIncludeEmailInSubjectSAN((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL) != 0);
        msaeTemplate.setIncludeEmailInSubjectDN((nameFlag & CT_FLAG_SUBJECT_REQUIRE_EMAIL) != 0);
        if ((nameFlag & CT_FLAG_SUBJECT_REQUIRE_COMMON_NAME) != 0) {
            msaeTemplate.setSubjectNameFormat("common_name");
        } else if ((nameFlag & CT_FLAG_SUBJECT_REQUIRE_DIRECTORY_PATH) != 0) {
            msaeTemplate.setSubjectNameFormat("fully_distinguished_name");
        } else if ((nameFlag & CT_FLAG_SUBJECT_REQUIRE_DNS_AS_CN) != 0) {
            msaeTemplate.setSubjectNameFormat("dns");
        } else if ((nameFlag & CT_FLAG_SUBJECT_ALT_REQUIRE_UPN) != 0) {
            msaeTemplate.setSubjectNameFormat("upn");
        }
        return msaeTemplate;
    }
    
    /**
     * Calculates enrollment permissions for this template given a users group membership
     * @param attributes SearchResult attributes from the Certificate Template in question.
     * @param groupMembership list containing SID for each AD group.
     * @return enrollment permissions boolean array in the format {autoenrollAllowed, enrollAllowed}
     */
    public static boolean[] getEnrollmentPermissions(final javax.naming.directory.Attributes attributes, final List<String> groupMembership) {
        final Attribute attribute = attributes.get("nTSecurityDescriptor");
        boolean autoenrollAllowed = false;
        boolean enrollAllowed = false;
        if (attribute == null) {
            return new boolean[] {autoenrollAllowed, enrollAllowed};
        }
        try {
            byte[] securityDescription = (byte[]) attribute.get();
            final SDDL sddl = new SDDL(securityDescription);
            final List<ACE> accessControlEntries = sddl.getDacl().getAces();
            for (ACE ace : accessControlEntries) {
                if (ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE && ace.getObjectType() != null
                        && GUID.getGuidAsString(ace.getObjectType()).equals(AD_ACCESS_TYPE_AUTOENROLL)
                        && groupMembership.contains(ace.getSid().toString())) {
                    autoenrollAllowed = true;
                }
                if (ace.getType() == AceType.ACCESS_ALLOWED_OBJECT_ACE_TYPE && ace.getObjectType() != null
                        && GUID.getGuidAsString(ace.getObjectType()).equals(AD_ACCESS_TYPE_ENROLL)
                        && groupMembership.contains(ace.getSid().toString())) {
                    enrollAllowed = true;
                }
                if (!autoenrollAllowed && !enrollAllowed && ace.getType() == AceType.ACCESS_ALLOWED_ACE_TYPE) {
                    // Check if "All extended rights" or "Full control" is allowed
                    for (ObjectRight objectRight : ace.getRights().getObjectRights()) {
                        // ACE allows all extended rights (incl. enrollment) OR "Full control" 
                        if ((objectRight.name().equals(ObjectRight.CR.name()) || objectRight.name().equals(ObjectRight.GA.name()))
                                && groupMembership.contains(ace.getSid().toString())) {
                            if (log.isDebugEnabled()) {
                                log.debug("ACE allows all extended rights on the group: " + ace.getSid().toString());
                            }
                            return new boolean[] { true, true };
                        }
                    }
                }
            }
        } catch (NamingException e) {
            log.warn("Could find attributeId 'nTSecurityDescriptor' in AD search results");
        }
        return new boolean[] {autoenrollAllowed, enrollAllowed};
    }
    
    /**
     * Performs bitwise AND on 'msPKI-Enrollment-Flag' from the Certificate Template 
     * over all possible enrollment flags for XCEP. Note that these flags doesn't include
     * all possible 'msPKI-Enrollment-Flag', hence we cannot simply copy the AD flag to the response.
     * @param attributes SearchResults attribute
     * @return effective enrollment flag.
     */
    public static Long getEnrollmentFlag(final javax.naming.directory.Attributes attributes) {
        final String enrollmentFlag = getAttributeString(attributes, "msPKI-Enrollment-Flag");
        if (enrollmentFlag == null) {
            return null;
        }
        Long adEnrollment = Long.valueOf(enrollmentFlag);
        return (adEnrollment & CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS) + (adEnrollment & CT_FLAG_PUBLISH_TO_DS)
                + (adEnrollment & CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE)
                + (adEnrollment & CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT) + (adEnrollment & CT_FLAG_USER_INTERACTION_REQUIRED)
                + (adEnrollment & CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE)
                + (adEnrollment & CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL);
    }
    
    public static BigInteger getTimePeriodFromFileTime(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        if (attribute == null) {
            return BigInteger.valueOf(0);
        }
        try {
            final byte[] fileTime = (byte[]) attribute.get();
            long fileTimeMillis = TimeUnitFormat.fileTimeToMillis(fileTime);
            return BigInteger.valueOf(fileTimeMillis / 1000);
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return BigInteger.valueOf(0);
        }
    }
    
    public static String getAttributeString(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        if (attribute == null) {
            return null;
        }
        try {
            return (String) attribute.get();
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return null;
        }
    }
    
    public static Long getAttributeLong(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        if (attribute == null) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return null;
        }
        try {
            return Long.parseLong(String.valueOf(attribute.get()));
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return null;
        }
    }
    
    public static long getAttributePrimitiveLong(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        if (attribute == null) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return 0;
        }
        try {
            return Long.parseLong((String)attribute.get());
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return 0;
        }
    }
    
    public static String[] getAttributeStringArray(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        final List<String> attributeValues = new ArrayList<>();
        if (attribute == null) {
            return new String[] {};
        }
        try {
            final NamingEnumeration<?> values = attribute.getAll();
            while (values.hasMore()) {
                attributeValues.add((String) values.next());
            }
            String[] attributeStrings = new String[attributeValues.size()];
            return attributeValues.toArray(attributeStrings);
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return new String[] {};
        }
    }
    
    public static String[] getAttributeStringArrayFromBinary(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        if (attribute == null) {
            return new String[]{};
        }
        try {
            byte[] bytes = (byte[]) attribute.get();
            String[] keyUsages = new String[bytes.length];
            int i = 0;
            for (byte b : bytes) {
                keyUsages[i++] = String.valueOf(b & 0xff);
            }
            return keyUsages;
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return new String[] {};
        }
    }
    
    public static List<String> getAttributeTokenGroups(final javax.naming.directory.Attributes attributes, final String attributeId) {
        final Attribute attribute = attributes.get(attributeId);
        final List<String> attributeValues = new ArrayList<>();
        if (attribute == null) {
            return new ArrayList<>();
        }
        try {
            final NamingEnumeration<?> tokens = attribute.getAll();
            while (tokens.hasMore()) {
                byte[] sidBytes = (byte[])tokens.next();
                try {
                    attributeValues.add(SID.parse(sidBytes).toString());
                } catch (IllegalArgumentException e) {
                    log.warn("Error parsing user group");
                }
            }
        } catch (NamingException e) {
            log.warn("Could find attributeId '" + attributeId + "' in AD search results");
            return new ArrayList<>();
        }
        return attributeValues;
    }
    
}
