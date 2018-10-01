/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.endentity;

import java.io.Serializable;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.text.DateFormat;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.time.DateUtils;
import org.apache.commons.lang.time.FastDateFormat;
import org.apache.log4j.Logger;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.DecoderException;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.cesecore.util.ValidityDate;

/**
 * The model representation of Extended Information about a user. It's used for non-searchable data about a user,
 * like a image, in an effort to minimize the need for database alterations
 *
 * TODO: Clean out whatever final static variables which aren't externally references.
 *
 * @version $Id$
 *
 */
public class ExtendedInformation extends UpgradeableDataHashMap implements Serializable {

    public static final String TYPE = "type";
    /** Different types of implementations of extended information, can be used to have different implementing classes of extended information */
    public static final int TYPE_BASIC = 0;

    private static final Logger log = Logger.getLogger(ExtendedInformation.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static final long serialVersionUID = 3981761824188420320L;

    private static final float LATEST_VERSION = 4;


    /**
     * Used to store subject directory attributes, which are put in an extension in the certificate. SubjectDirectoryAttributes are standard
     * attributes, see rfc3280
     */
    public  static final String SUBJECTDIRATTRIBUTES = "subjectdirattributes";
    /** Custom data can be used by various custom work-flows and other non-standard things to store information needed */
    public  static final String CUSTOMDATA = "customdata_";

    /**
     * Extension data can be used by the BasicCertificateExtension or custom
     * certificate extensions to store data to be used when creating the
     * extension such as the extension value.
     */
    public static final String EXTENSIONDATA = "extensiondata_";

    /**
     * Identifier for Custom data holding a end time when the users certificate should be valid extInfo.setCustomData(EndEntityProfile.STARTTIME, "");
     */
    public  static final String CUSTOM_STARTTIME = "STARTTIME"; // EndEntityProfile.STARTTIME;
    /**
     * Identifier for Custom data holding a end time when the users certificate should be valid extInfo.setCustomData(EndEntityProfile.ENDTIME, "");
     */
    public  static final String CUSTOM_ENDTIME = "ENDTIME"; // EndEntityProfile.ENDTIME;

    /** The (optional) revocation status a certificate issued to this user will have, immediately upon issuance. */
    public  static final String CUSTOM_REVOCATIONREASON = "REVOCATIONREASON";

    /** The subject DN exactly as requested in the UserDataVOWS object.
     * Should be stored B64 encoded to avoid possible XML/database encoding issues, getRawSubjectDn does decoding if it is encoded */
    public static final String RAWSUBJECTDN = "RAWSUBJECTDN";

    /** The counter is a counter for how many failed login attempts that can be performed before the userstatus is changed to GENERATED */
    private static final String REMAININGLOGINATTEMPTS = "remainingloginattempts";

    /** The maximum number of login attempts before the user is locked by setting its status to GENERATED */
    private static final String MAXFAILEDLOGINATTEMPTS = "maxfailedloginattempts";

    /** Default value for how many failed login attempts are allow = -1 (unlimited) */
    public static final int DEFAULT_MAXLOGINATTEMPTS = -1;

    /** Default value for how many of the allowed failed login attempts that are remaining = -1 (unlimited) */
    public static final int DEFAULT_REMAININGLOGINATTEMPTS = -1;

    /** Map key for certificate serial number */
    private  static final String CERTIFICATESERIALNUMBER = "CERTIFICATESERIALNUMBER";
    private static final Object NAMECONSTRAINTS_PERMITTED = "nameconstraints_permitted";
    private static final Object NAMECONSTRAINTS_EXCLUDED = "nameconstraints_excluded";

    /** Keystore specifications used for enrolling end entity user with key-pair generated on a server side (KickAssRA).*/
    private static String KEYSTORE_ALGORITHM_SUBTYPE = "KEYSTORE_ALGORITHM_SUBTYPE";
    private static String KEYSTORE_ALGORITHM_TYPE = "KEYSTORE_ALGORITHM_TYPE";

    /** The ID of the approval request that was submitted to create the end entity */
    private static String ADD_EE_APPROVAL_REQUEST_ID = "ADD_EE_APPROVAL_REQUEST_ID";
    /** The IDs of the approval requests that were submitted to edit the end entity */
    private static String EDIT_EE_APPROVAL_REQUEST_IDS = "EDIT_EE_APPROVAL_REQUEST_IDS";
    /** The IDs of the approval requests that were submitted to revoke the end entity */
    private static String REVOKE_EE_APPROVAL_REQUEST_IDS = "REVOKE_EE_APPROVAL_REQUEST_IDS";

    /** Certificate request used for enrolling end entity user with public key provided by user (KickAssRA). */
    private static String CERTIFICATE_REQUEST = "CERTIFICATE_REQUEST";


    /** Creates a new instance of ExtendedInformation */
    public ExtendedInformation() {
        setType(TYPE_BASIC);
        data.put(SUBJECTDIRATTRIBUTES, "");
        setMaxLoginAttempts(DEFAULT_MAXLOGINATTEMPTS);
        setRemainingLoginAttempts(DEFAULT_REMAININGLOGINATTEMPTS);
        setCertificateRequest(null);
    }

    /**
     * Copy constructor
     *
     * @param extendedInformation the ExtendedInformation map top copy
     */
    public ExtendedInformation(final ExtendedInformation extendedInformation) {
        this.data = extendedInformation.getClonedData();
    }

    /** @return The keystore algorithm subtype is the key length for RSA/DSA ('2046', '4096',...) or curve specification for ECDSA
     *  ('brainpoolP224r1', 'prime239v1', 'secp256k1'...) if it was provided during user enrollment request, null otherwise. Default: null*/
    public String getKeyStoreAlgorithmSubType(){
        return (String) data.get(KEYSTORE_ALGORITHM_SUBTYPE);
    }

    public void setKeyStoreAlgorithmSubType(String keyStoreAlgorithmSubType){
        data.put(KEYSTORE_ALGORITHM_SUBTYPE, keyStoreAlgorithmSubType);
    }

    /** @return The keystore algorithm type (RSA, DSA, ECDSA) if it was provided during user enrollment request, null otherwise. Default: null*/
    public String getKeyStoreAlgorithmType(){
        return (String) data.get(KEYSTORE_ALGORITHM_TYPE);
    }

    public void setKeyStoreAlgorithmType(String keyStoreAlgorithmType){
        data.put(KEYSTORE_ALGORITHM_TYPE, keyStoreAlgorithmType);
    }

    /** @return The certificate request in binary asn.1 form if it was provided during user enrollment request, null otherwise.*/
    public byte[] getCertificateRequest() {
        // For legacy reasons (<EJBCA 6.7.0) the data in the database may be stored in binary format.
        // We will make the optimistic assumption that it is b64 encoded first
        final Object o = data.get(CERTIFICATE_REQUEST);
        if (o == null) {
            return null;
        }
        try {
            return Base64.decode(((String)o).getBytes(StandardCharsets.UTF_8));
        } catch (DecoderException | ClassCastException e) {
            // Not base 64 encoded, return binary bytes
            return (byte[])o;
        }
    }

    /**
     * @param certificateRequest a CSR in binary asn.1 format
     */
    public void setCertificateRequest(byte[] certificateRequest) {
        // Store it in the database in base64 encoded format, without CSR headers or linebreaks (or null)
        final String str = certificateRequest == null ? null : new String(Base64.encode(certificateRequest), StandardCharsets.UTF_8);
        data.put(CERTIFICATE_REQUEST, str);
    }

    public String getSubjectDirectoryAttributes() {
        String ret = (String) data.get(SUBJECTDIRATTRIBUTES);
        if (ret == null) {
            ret = "";
        }
        return ret;
    }

    public void setSubjectDirectoryAttributes(String subjdirattr) {
        if (subjdirattr == null) {
            data.put(SUBJECTDIRATTRIBUTES, "");
        } else {
            data.put(SUBJECTDIRATTRIBUTES, subjdirattr);
        }
    }

    /**
     * @return The number of remaining allowed failed login attempts or -1 for unlimited
     */
    public int getRemainingLoginAttempts() {
        return Integer.valueOf(data.get(REMAININGLOGINATTEMPTS).toString());
    }

    /**
     * Set the number of remaining login attempts. -1 means unlimited.
     *
     * @param remainingLoginAttempts
     *            The number to set
     */
    public void setRemainingLoginAttempts(int remainingLoginAttempts) {
        data.put(REMAININGLOGINATTEMPTS, Integer.valueOf(remainingLoginAttempts));
    }

    /**
     * @return The maximum number of allowed failed login attempts or -1 for unlimited
     */
    public int getMaxLoginAttempts() {
        return Integer.valueOf(data.get(MAXFAILEDLOGINATTEMPTS).toString());
    }

    /**
     * @return The certificate validity end time or null if not specified.
     */
    public String getCertificateEndTime() {
        final Object o = data.get(CUSTOMDATA + CUSTOM_ENDTIME);
        if (o == null) {
            return null;
        }
        return o.toString();
    }

    /**
     * Set the certificate validity end time to a user-defined value.
     * @param value The certificate validity
     */
    public void setCertificateEndTime(final String value) {
        data.put(CUSTOMDATA + CUSTOM_ENDTIME, value);
    }

    /**
     * Set the number of maximum allowed failed login attempts. -1 means unlimited.
     *
     * @param remainingLoginAttempts
     *            The number to set
     */
    public void setMaxLoginAttempts(int maxLoginAttempts) {
        data.put(MAXFAILEDLOGINATTEMPTS, Integer.valueOf(maxLoginAttempts));
    }

    /**
     * @return the serial number to be used for the certificate or null if no number defined.
     */
    public BigInteger certificateSerialNumber() {
        final String s = (String) this.data.get(CERTIFICATESERIALNUMBER);
        if (s == null) {
            return null;
        }
        return new BigInteger(Base64.decode(s));
    }

    /**
     * @param sn
     *            the serial number to be used for the certificate
     */
    public void setCertificateSerialNumber(BigInteger sn) {
        if (sn == null) {
            this.data.remove(CERTIFICATESERIALNUMBER);
            return;
        }
        final String s = new String(Base64.encode(sn.toByteArray()));
        this.data.put(CERTIFICATESERIALNUMBER, s);
    }

    /**
     * Returns the issuance revocation code configured on the end entity extended information.
     *
     * @param data user data
     * @return issuance revocation code configured on the end entity extended information, a constant from RevokedCertInfo. Default
     *         RevokedCertInfo.NOT_REVOKED.
     */
    public int getIssuanceRevocationReason() {
        int ret = RevokedCertInfo.NOT_REVOKED;
            final String revocationReason = getCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON);
            if (revocationReason != null) {
                ret = Integer.valueOf(revocationReason);
            }
        if (log.isDebugEnabled()) {
            log.debug("User issuance revocation reason is " + ret);
        }
        return ret;
    }

    /**
    * Sets the issuance revocation code configured on the end entity extended information.
    *
    * @param reason issuance revocation code, a constant from RevokedCertInfo such as RevokedCertInfo.REVOCATION_REASON_CERTIFICATEHOLD.
    */
    public void setIssuanceRevocationReason(int reason) {
    	setCustomData(ExtendedInformation.CUSTOM_REVOCATIONREASON, "" + reason);
    }

    /** @return Encoded name constraints to permit */
    public List<String> getNameConstraintsPermitted() {
        String value = (String) data.get(NAMECONSTRAINTS_PERMITTED);
        if (value == null || value.isEmpty()) {
            return null;
        }
        return new ArrayList<String>(Arrays.asList(value.split(";")));
    }

    public void setNameConstraintsPermitted(List<String> encodedNames) {
        if (encodedNames == null) {
            data.remove(NAMECONSTRAINTS_PERMITTED);
        } else {
            data.put(NAMECONSTRAINTS_PERMITTED, StringUtils.join(encodedNames, ';'));
        }
    }

    /** @return Encoded name constraints to exclude */
    public List<String> getNameConstraintsExcluded() {
        String value = (String) data.get(NAMECONSTRAINTS_EXCLUDED);
        if (value == null || value.isEmpty()) {
            return null;
        }
        return new ArrayList<String>(Arrays.asList(value.split(";")));
    }

    public void setNameConstraintsExcluded(List<String> encodedNames) {
        if (encodedNames == null) {
            data.remove(NAMECONSTRAINTS_EXCLUDED);
        } else {
            data.put(NAMECONSTRAINTS_EXCLUDED, StringUtils.join(encodedNames, ';'));
        }
    }

    /** @return the subject DN exactly as requested (via WS ) */
    public String getRawSubjectDn() {
        final String value = (String) data.get(RAWSUBJECTDN);
        if (value == null || value.isEmpty()) {
            return null;
        }
        // It could/should B64 encoded to avoid XML baddies
        return StringTools.getBase64String(value);
    }

    /**
     * Gets generic string data from the ExtendedInformation map.
     */
    public String getMapData(String key) {
        String ret = null;
        Object o = data.get(key);
        if (o instanceof String) {
            ret = (String) o;
        }
        return ret;
    }

    /**
     * Sets generic string data in the ExtendedInformation map.
     */
    public void setMapData(String key, String value) {
        data.put(key, value);
    }

    /**
     * Special method used to retrieve custom set userdata
     *
     * @returns The data or null if no such data have been set for the user
     */
    public String getCustomData(String key) {
        String retval = (String) data.get(CUSTOMDATA + key);
        return retval;
    }

    /**
     * Sets extension data.
     * @param customly defined key to store the data with
     * @param the string representation of the data
     */
    public void setExtensionData(String key, String value) {
    	data.put(EXTENSIONDATA + key, value);
    }

    /**
     * Special method used to retrieve custom extension data.
     * @returns The data or null if no such data have been set for the user
     */
    public String getExtensionData(String key){
    	String retval = (String) data.get(EXTENSIONDATA + key);
    	return retval;
    }

    /**
     * @return Set containing all extension OIDs
     */
    public Set<String> getExtensionDataOids() {
        final Set<String> oids = new HashSet<>();
        for (Object o : data.keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                    String oidString = key.substring(ExtendedInformation.EXTENSIONDATA.length());
                    oids.add(CertTools.getOidFromString(oidString));
                }
            }
        }
        return oids;
    }
    
    /**
     *
     * @param customly
     *            defined key to store the data with
     * @param the
     *            string representation of the data
     */
    public void setCustomData(String key, String value) {
        data.put(CUSTOMDATA + key, value);
    }

    /** Function required by XMLEncoder to do a proper serialization. */
    public void setData(Object hmData) {
        loadData(hmData);
    }

    /** Function required by XMLEncoder to do a proper serialization. */
    public Object getData() {
        return saveData();
    }

    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /** Implementation of UpgradableDataHashMap function upgrade. */

    @Override
    public void upgrade() {
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade
            String msg = intres.getLocalizedMessage("endentity.extendedinfoupgrade", new Float(getVersion()));
            log.info(msg);

            if (data.get(SUBJECTDIRATTRIBUTES) == null) {
                data.put(SUBJECTDIRATTRIBUTES, "");
            }
            if (data.get(MAXFAILEDLOGINATTEMPTS) == null) {
                setMaxLoginAttempts(DEFAULT_MAXLOGINATTEMPTS);
            }
            if (data.get(REMAININGLOGINATTEMPTS) == null) {
                setRemainingLoginAttempts(DEFAULT_REMAININGLOGINATTEMPTS);
            }
            // In EJBCA 4.0.0 we changed the date format
        	if (getVersion() < 3) {
        		final DateFormat oldDateFormat = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT, Locale.US);
        		final FastDateFormat newDateFormat = FastDateFormat.getInstance("yyyy-MM-dd HH:mm");
        		try {
        			final String oldCustomStartTime = getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
        			if ( !isEmptyOrRelative(oldCustomStartTime) ) {
        				// We use an absolute time format, so we need to upgrade
            			final String newCustomStartTime = newDateFormat.format(oldDateFormat.parse(oldCustomStartTime));
    					setCustomData(ExtendedInformation.CUSTOM_STARTTIME, newCustomStartTime);
    					if (log.isDebugEnabled()) {
    						log.debug("Upgraded " + ExtendedInformation.CUSTOM_STARTTIME + " from \"" + oldCustomStartTime + "\" to \"" + newCustomStartTime + "\" in ExtendedInformation.");
    					}
        			}
				} catch (ParseException e) {
					log.error("Unable to upgrade " + ExtendedInformation.CUSTOM_STARTTIME + " in extended user information.", e);
				}
        		try {
        			final String oldCustomEndTime = getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
        			if ( !isEmptyOrRelative(oldCustomEndTime) ) {
        				// We use an absolute time format, so we need to upgrade
            			final String newCustomEndTime = newDateFormat.format(oldDateFormat.parse(oldCustomEndTime));
    					setCustomData(ExtendedInformation.CUSTOM_ENDTIME, newCustomEndTime);
    					if (log.isDebugEnabled()) {
    						log.debug("Upgraded " + ExtendedInformation.CUSTOM_ENDTIME + " from \"" + oldCustomEndTime + "\" to \"" + newCustomEndTime + "\" in ExtendedInformation.");
    					}
        			}
				} catch (ParseException e) {
					log.error("Unable to upgrade " + ExtendedInformation.CUSTOM_ENDTIME + " in extended user information.", e);
				}
        	}
        	// In 4.0.2 we further specify the storage format by saying that UTC TimeZone is implied instead of local server time
        	if (getVersion() < 4) {
        		final String[] timePatterns = {"yyyy-MM-dd HH:mm"};
    			final String oldStartTime = getCustomData(ExtendedInformation.CUSTOM_STARTTIME);
    			if (!isEmptyOrRelative(oldStartTime)) {
            		try {
            			final String newStartTime = ValidityDate.formatAsUTC(DateUtils.parseDateStrictly(oldStartTime, timePatterns));
    					setCustomData(ExtendedInformation.CUSTOM_STARTTIME, newStartTime);
    					if (log.isDebugEnabled()) {
    						log.debug("Upgraded " + ExtendedInformation.CUSTOM_STARTTIME + " from \"" + oldStartTime + "\" to \"" + newStartTime + "\" in EndEntityProfile.");
    					}
					} catch (ParseException e) {
						log.error("Unable to upgrade " + ExtendedInformation.CUSTOM_STARTTIME + " to UTC in EndEntityProfile! Manual interaction is required (edit and verify).", e);
					}
    			}
    			final String oldEndTime = getCustomData(ExtendedInformation.CUSTOM_ENDTIME);
    			if (!isEmptyOrRelative(oldEndTime)) {
    				// We use an absolute time format, so we need to upgrade
					try {
						final String newEndTime = ValidityDate.formatAsUTC(DateUtils.parseDateStrictly(oldEndTime, timePatterns));
						setCustomData(ExtendedInformation.CUSTOM_ENDTIME, newEndTime);
						if (log.isDebugEnabled()) {
							log.debug("Upgraded " + ExtendedInformation.CUSTOM_ENDTIME + " from \"" + oldEndTime + "\" to \"" + newEndTime + "\" in EndEntityProfile.");
						}
					} catch (ParseException e) {
						log.error("Unable to upgrade " + ExtendedInformation.CUSTOM_ENDTIME + " to UTC in EndEntityProfile! Manual interaction is required (edit and verify).", e);
					}
    			}
        	}
            data.put(VERSION,  Float.valueOf(LATEST_VERSION));
        }
    }

    /** @return true if argument is null, empty or in the relative time format. */
    private boolean isEmptyOrRelative(final String time) {
    	return (time == null || time.length()==0 || time.matches("^\\d+:\\d?\\d:\\d?\\d$"));
    }

    /**
     * Method that returns the classpath to the this or inheriting classes.
     *
     * @return String containing the classpath.
     */
    public int getType() {
        return ((Integer) data.get(TYPE)).intValue();
    }

    /**
     * Method used to specify which kind of object that should be created during deserialization process.
     *
     * Inheriting class should call 'setClassPath(this) in it's constructor.
     *
     * @param object
     */
    private void setType(int type) {
        data.put(TYPE, type);
    }


    public Integer getAddEndEntityApprovalRequestId() {
        Object id = data.get(ADD_EE_APPROVAL_REQUEST_ID);
        if(id != null) {
            return (Integer) id;
        }
        return null;
    }

    public void setAddEndEntityApprovalRequestId(Integer requestId) {
        data.put(ADD_EE_APPROVAL_REQUEST_ID, requestId);
    }

    public List<Integer> getEditEndEntityApprovalRequestIds() {
        @SuppressWarnings("unchecked")
        ArrayList<Integer> ids = (ArrayList<Integer>) data.get(EDIT_EE_APPROVAL_REQUEST_IDS);
        if(ids != null) {
            return ids;
        }
        return new ArrayList<Integer>();
    }

    public void addEditEndEntityApprovalRequestId(Integer requestId) {
        Object obj = data.get(EDIT_EE_APPROVAL_REQUEST_IDS);
        @SuppressWarnings("unchecked")
        ArrayList<Integer> ids = obj==null? new ArrayList<Integer>() : (ArrayList<Integer>) obj;
        ids.add(requestId);
        data.put(EDIT_EE_APPROVAL_REQUEST_IDS, ids);
    }

    public List<Integer> getRevokeEndEntityApprovalRequestIds() {
        @SuppressWarnings("unchecked")
        ArrayList<Integer> ids = (ArrayList<Integer>) data.get(REVOKE_EE_APPROVAL_REQUEST_IDS);
        if(ids != null) {
            return ids;
        }
        return new ArrayList<Integer>();
    }

    public void addRevokeEndEntityApprovalRequestId(Integer requestId) {
        @SuppressWarnings("unchecked")
        List<Integer> obj = (List<Integer>) data.get(REVOKE_EE_APPROVAL_REQUEST_IDS);
        List<Integer> ids = obj==null? new ArrayList<Integer>() : obj;
        ids.add(requestId);
        data.put(REVOKE_EE_APPROVAL_REQUEST_IDS, ids);
    }

}
