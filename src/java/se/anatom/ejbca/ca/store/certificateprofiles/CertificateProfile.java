package se.anatom.ejbca.ca.store.certificateprofiles;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.util.UpgradeableDataHashMap;

import java.io.Serializable;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;


/**
 * CertificateProfile is a basic class used to customize a certificate configuration or be
 * inherited by fixed certificate profiles.
 *
 * @version $Id: CertificateProfile.java,v 1.16 2003-06-26 11:43:23 anatom Exp $
 */
public class CertificateProfile extends UpgradeableDataHashMap implements Serializable, Cloneable {
    // Default Values
    public static final float LATEST_VERSION = 6;

    /** KeyUsage constants */
    public static final int DIGITALSIGNATURE = 0;
    public static final int NONREPUDIATION = 1;
    public static final int KEYENCIPHERMENT = 2;
    public static final int DATAENCIPHERMENT = 3;
    public static final int KEYAGREEMENT = 4;
    public static final int KEYCERTSIGN = 5;
    public static final int CRLSIGN = 6;
    public static final int ENCIPHERONLY = 7;
    public static final int DECIPHERONLY = 8;

    /** Extended key usage constants */
    public static final int ANYEXTENDEDKEYUSAGE = 0;
    public static final int SERVERAUTH = 1;
    public static final int CLIENTAUTH = 2;
    public static final int CODESIGNING = 3;
    public static final int EMAILPROTECTION = 4;
    public static final int IPSECENDSYSTEM = 5;
    public static final int IPSECTUNNEL = 6;
    public static final int IPSECUSER = 7;
    public static final int TIMESTAMPING = 8;
    public static final int SMARTCARDLOGON = 9;
    private static final String[] EXTENDEDKEYUSAGEOIDSTRINGS = {
        "1.3.6.1.5.5.7.3.0", "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2", "1.3.6.1.5.5.7.3.3",
        "1.3.6.1.5.5.7.3.4", "1.3.6.1.5.5.7.3.5", "1.3.6.1.5.5.7.3.6", "1.3.6.1.5.5.7.3.7",
        "1.3.6.1.5.5.7.3.8", "1.3.6.1.4.1.311.20.2.2"
    };
    public static final String TRUE = "true";
    public static final String FALSE = "false";
    public static final int TYPE_ENDENTITY = SecConst.CERTTYPE_ENDENTITY;
    public static final int TYPE_CA = SecConst.CERTTYPE_CA;
    public static final int TYPE_ROOTCA = SecConst.CERTTYPE_ROOTCA;
    public static final int NUMBER_OF_TYPES = 3;

    /** Supported certificate versions. */
    public static final String VERSION_X509V3 = "X509v3";
    public static final String CERTIFICATEPROFILENAME = "CUSTOM";

    // protected fields.
    protected static final String CERTVERSION = "certversion";
    protected static final String VALIDITY = "validity";
    protected static final String USEBASICCONSTRAINTS = "usebasicconstrants";
    protected static final String BASICCONSTRAINTSCRITICAL = "basicconstraintscritical";
    protected static final String USEKEYUSAGE = "usekeyusage";
    protected static final String KEYUSAGECRITICAL = "keyusagecritical";
    protected static final String USESUBJECTKEYIDENTIFIER = "usesubjectkeyidentifier";
    protected static final String SUBJECTKEYIDENTIFIERCRITICAL = "subjectkeyidentifiercritical";
    protected static final String USEAUTHORITYKEYIDENTIFIER = "useauthoritykeyidentifier";
    protected static final String AUTHORITYKEYIDENTIFIERCRITICAL = "authoritykeyidentifiercritical";
    protected static final String USECRLNUMBER = "usecrlnumber";
    protected static final String CRLNUMBERCRITICAL = "crlnumbercritical";
    protected static final String USESUBJECTALTERNATIVENAME = "usesubjectalternativename";
    protected static final String SUBJECTALTERNATIVENAMECRITICAL = "subjectalternativenamecritical";
    protected static final String USECRLDISTRIBUTIONPOINT = "usecrldistributionpoint";
    protected static final String CRLDISTRIBUTIONPOINTCRITICAL = "crldistributionpointcritical";
    protected static final String CRLDISTRIBUTIONPOINTURI = "crldistributionpointuri";
    protected static final String USECERTIFICATEPOLICIES = "usecertificatepolicies";
    protected static final String CERTIFICATEPOLICIESCRITICAL = "certificatepoliciescritical";
    protected static final String CERTIFICATEPOLICYID = "certificatepolicyid";
    protected static final String AVAILABLEBITLENGTHS = "availablebitlengths";
    protected static final String KEYUSAGE = "keyusage";
    protected static final String MINIMUMAVAILABLEBITLENGTH = "minimumavailablebitlength";
    protected static final String MAXIMUMAVAILABLEBITLENGTH = "maximumavailablebitlength";
    public static final String TYPE = "type";
    protected static final String ALLOWKEYUSAGEOVERRIDE = "allowkeyusageoverride";
    protected static final String USEEXTENDEDKEYUSAGE = "useextendedkeyusage";
    protected static final String EXTENDEDKEYUSAGE = "extendedkeyusage";
    protected static final String EXTENDEDKEYUSAGECRITICAL = "extendedkeyusagecritical";

    // Public Methods

    /**
     * Creates a new instance of CertificateProfile
     */
    public CertificateProfile() {
        setCertificateVersion(VERSION_X509V3);
        setValidity(730);

        setUseBasicConstraints(true);
        setBasicConstraintsCritical(true);

        setUseSubjectKeyIdentifier(true);
        setSubjectKeyIdentifierCritical(false);

        setUseAuthorityKeyIdentifier(true);
        setAuthorityKeyIdentifierCritical(false);

        setUseSubjectAlternativeName(true);
        setSubjectAlternativeNameCritical(false);

        setUseCRLDistributionPoint(false);
        setCRLDistributionPointCritical(false);
        setCRLDistributionPointURI("");

        setUseCertificatePolicies(false);
        setCertificatePoliciesCritical(false);
        setCertificatePolicyId("2.5.29.32.0");

        setType(TYPE_ENDENTITY);

        int[] bitlengths = { 512, 1024, 2048, 4096 };
        setAvailableBitLengths(bitlengths);

        setUseKeyUsage(true);
        setKeyUsage(new boolean[9]);
        setAllowKeyUsageOverride(true);
        setKeyUsageCritical(true);

        setUseExtendedKeyUsage(false);
        setExtendedKeyUsage(new ArrayList());
        setExtendedKeyUsageCritical(false);
    }

    // Public Methods.

    /**
     * Returns the version of the certificate, should be one of the VERSION_ constants defined in
     * CertificateProfile class.
     *
     * @return DOCUMENT ME!
     */
    public String getCertificateVersion() {
        return (String) data.get(CERTVERSION);
    }

    /**
     * Sets the version of the certificate, should be one of the VERSION_ constants defined in
     * CertificateProfile class.
     *
     * @param version DOCUMENT ME!
     */
    public void setCertificateVersion(String version) {
        data.put(CERTVERSION, version);
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public long getValidity() {
        return ((Long) data.get(VALIDITY)).longValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param validity DOCUMENT ME!
     */
    public void setValidity(long validity) {
        data.put(VALIDITY, new Long(validity));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseBasicConstraints() {
        return ((Boolean) data.get(USEBASICCONSTRAINTS)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param usebasicconstraints DOCUMENT ME!
     */
    public void setUseBasicConstraints(boolean usebasicconstraints) {
        data.put(USEBASICCONSTRAINTS, Boolean.valueOf(usebasicconstraints));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getBasicConstraintsCritical() {
        return ((Boolean) data.get(BASICCONSTRAINTSCRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param basicconstraintscritical DOCUMENT ME!
     */
    public void setBasicConstraintsCritical(boolean basicconstraintscritical) {
        data.put(BASICCONSTRAINTSCRITICAL, Boolean.valueOf(basicconstraintscritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseKeyUsage() {
        return ((Boolean) data.get(USEKEYUSAGE)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param usekeyusage DOCUMENT ME!
     */
    public void setUseKeyUsage(boolean usekeyusage) {
        data.put(USEKEYUSAGE, Boolean.valueOf(usekeyusage));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getKeyUsageCritical() {
        return ((Boolean) data.get(KEYUSAGECRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param keyusagecritical DOCUMENT ME!
     */
    public void setKeyUsageCritical(boolean keyusagecritical) {
        data.put(KEYUSAGECRITICAL, Boolean.valueOf(keyusagecritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseSubjectKeyIdentifier() {
        return ((Boolean) data.get(USESUBJECTKEYIDENTIFIER)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param usesubjectkeyidentifier DOCUMENT ME!
     */
    public void setUseSubjectKeyIdentifier(boolean usesubjectkeyidentifier) {
        data.put(USESUBJECTKEYIDENTIFIER, Boolean.valueOf(usesubjectkeyidentifier));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getSubjectKeyIdentifierCritical() {
        return ((Boolean) data.get(SUBJECTKEYIDENTIFIERCRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param subjectkeyidentifiercritical DOCUMENT ME!
     */
    public void setSubjectKeyIdentifierCritical(boolean subjectkeyidentifiercritical) {
        data.put(SUBJECTKEYIDENTIFIERCRITICAL, Boolean.valueOf(subjectkeyidentifiercritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseAuthorityKeyIdentifier() {
        return ((Boolean) data.get(USEAUTHORITYKEYIDENTIFIER)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param useauthoritykeyidentifier DOCUMENT ME!
     */
    public void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier) {
        data.put(USEAUTHORITYKEYIDENTIFIER, Boolean.valueOf(useauthoritykeyidentifier));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getAuthorityKeyIdentifierCritical() {
        return ((Boolean) data.get(AUTHORITYKEYIDENTIFIERCRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param authoritykeyidentifiercritical DOCUMENT ME!
     */
    public void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical) {
        data.put(AUTHORITYKEYIDENTIFIERCRITICAL, Boolean.valueOf(authoritykeyidentifiercritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseSubjectAlternativeName() {
        return ((Boolean) data.get(USESUBJECTALTERNATIVENAME)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param usesubjectalternativename DOCUMENT ME!
     */
    public void setUseSubjectAlternativeName(boolean usesubjectalternativename) {
        data.put(USESUBJECTALTERNATIVENAME, Boolean.valueOf(usesubjectalternativename));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getSubjectAlternativeNameCritical() {
        return ((Boolean) data.get(SUBJECTALTERNATIVENAMECRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param subjectalternativenamecritical DOCUMENT ME!
     */
    public void setSubjectAlternativeNameCritical(boolean subjectalternativenamecritical) {
        data.put(SUBJECTALTERNATIVENAMECRITICAL, Boolean.valueOf(subjectalternativenamecritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseCRLDistributionPoint() {
        return ((Boolean) data.get(USECRLDISTRIBUTIONPOINT)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param usecrldistributionpoint DOCUMENT ME!
     */
    public void setUseCRLDistributionPoint(boolean usecrldistributionpoint) {
        data.put(USECRLDISTRIBUTIONPOINT, Boolean.valueOf(usecrldistributionpoint));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getCRLDistributionPointCritical() {
        return ((Boolean) data.get(CRLDISTRIBUTIONPOINTCRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param crldistributionpointcritical DOCUMENT ME!
     */
    public void setCRLDistributionPointCritical(boolean crldistributionpointcritical) {
        data.put(CRLDISTRIBUTIONPOINTCRITICAL, Boolean.valueOf(crldistributionpointcritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCRLDistributionPointURI() {
        return (String) data.get(CRLDISTRIBUTIONPOINTURI);
    }

    /**
     * DOCUMENT ME!
     *
     * @param crldistributionpointuri DOCUMENT ME!
     */
    public void setCRLDistributionPointURI(String crldistributionpointuri) {
        if (crldistributionpointuri == null) {
            data.put(CRLDISTRIBUTIONPOINTURI, "");
        } else {
            data.put(CRLDISTRIBUTIONPOINTURI, crldistributionpointuri);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseCertificatePolicies() {
        return ((Boolean) data.get(USECERTIFICATEPOLICIES)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param usecertificatepolicies DOCUMENT ME!
     */
    public void setUseCertificatePolicies(boolean usecertificatepolicies) {
        data.put(USECERTIFICATEPOLICIES, Boolean.valueOf(usecertificatepolicies));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getCertificatePoliciesCritical() {
        return ((Boolean) data.get(CERTIFICATEPOLICIESCRITICAL)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param certificatepoliciescritical DOCUMENT ME!
     */
    public void setCertificatePoliciesCritical(boolean certificatepoliciescritical) {
        data.put(CERTIFICATEPOLICIESCRITICAL, Boolean.valueOf(certificatepoliciescritical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public String getCertificatePolicyId() {
        return (String) data.get(CERTIFICATEPOLICYID);
    }

    /**
     * DOCUMENT ME!
     *
     * @param policyid DOCUMENT ME!
     */
    public void setCertificatePolicyId(String policyid) {
        if (policyid == null) {
            data.put(CERTIFICATEPOLICYID, "");
        } else {
            data.put(CERTIFICATEPOLICYID, policyid);
        }
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getType() {
        return ((Integer) data.get(TYPE)).intValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param type DOCUMENT ME!
     */
    public void setType(int type) {
        data.put(TYPE, new Integer(type));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isTypeCA() {
        return ((Integer) data.get(TYPE)).intValue() == TYPE_CA;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isTypeRootCA() {
        return ((Integer) data.get(TYPE)).intValue() == TYPE_ROOTCA;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean isTypeEndEntity() {
        return ((Integer) data.get(TYPE)).intValue() == TYPE_ENDENTITY;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int[] getAvailableBitLengths() {
        ArrayList availablebitlengths = (ArrayList) data.get(AVAILABLEBITLENGTHS);
        int[] returnval = new int[availablebitlengths.size()];

        for (int i = 0; i < availablebitlengths.size(); i++) {
            returnval[i] = ((Integer) availablebitlengths.get(i)).intValue();
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param availablebitlengths DOCUMENT ME!
     */
    public void setAvailableBitLengths(int[] availablebitlengths) {
        ArrayList availbitlengths = new ArrayList(availablebitlengths.length);

        int minimumavailablebitlength = 99999999;
        int maximumavailablebitlength = 0;

        for (int i = 0; i < availablebitlengths.length; i++) {
            if (availablebitlengths[i] > maximumavailablebitlength) {
                maximumavailablebitlength = availablebitlengths[i];
            }

            if (availablebitlengths[i] < minimumavailablebitlength) {
                minimumavailablebitlength = availablebitlengths[i];
            }

            availbitlengths.add(new Integer(availablebitlengths[i]));
        }

        data.put(AVAILABLEBITLENGTHS, availbitlengths);
        data.put(MINIMUMAVAILABLEBITLENGTH, new Integer(minimumavailablebitlength));
        data.put(MAXIMUMAVAILABLEBITLENGTH, new Integer(maximumavailablebitlength));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getMinimumAvailableBitLength() {
        return ((Integer) data.get(MINIMUMAVAILABLEBITLENGTH)).intValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public int getMaximumAvailableBitLength() {
        return ((Integer) data.get(MAXIMUMAVAILABLEBITLENGTH)).intValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean[] getKeyUsage() {
        ArrayList keyusage = (ArrayList) data.get(KEYUSAGE);
        boolean[] returnval = new boolean[keyusage.size()];

        for (int i = 0; i < keyusage.size(); i++) {
            returnval[i] = ((Boolean) keyusage.get(i)).booleanValue();
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @param keyusageconstant DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getKeyUsage(int keyusageconstant) {
        return ((Boolean) ((ArrayList) data.get(KEYUSAGE)).get(keyusageconstant)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param keyusage DOCUMENT ME!
     */
    public void setKeyUsage(boolean[] keyusage) {
        ArrayList keyuse = new ArrayList(keyusage.length);

        for (int i = 0; i < keyusage.length; i++) {
            keyuse.add(Boolean.valueOf(keyusage[i]));
        }

        data.put(KEYUSAGE, keyuse);
    }

    /**
     * DOCUMENT ME!
     *
     * @param keyusageconstant DOCUMENT ME!
     * @param value DOCUMENT ME!
     */
    public void setKeyUsage(int keyusageconstant, boolean value) {
        ((ArrayList) data.get(KEYUSAGE)).set(keyusageconstant, Boolean.valueOf(value));
    }

    /**
     * DOCUMENT ME!
     *
     * @param override DOCUMENT ME!
     */
    public void setAllowKeyUsageOverride(boolean override) {
        data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.valueOf(override));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getAllowKeyUsageOverride() {
        return ((Boolean) data.get(ALLOWKEYUSAGEOVERRIDE)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param use DOCUMENT ME!
     */
    public void setUseExtendedKeyUsage(boolean use) {
        data.put(USEEXTENDEDKEYUSAGE, Boolean.valueOf(use));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getUseExtendedKeyUsage() {
        return ((Boolean) data.get(USEEXTENDEDKEYUSAGE)).booleanValue();
    }

    /**
     * DOCUMENT ME!
     *
     * @param critical DOCUMENT ME!
     */
    public void setExtendedKeyUsageCritical(boolean critical) {
        data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.valueOf(critical));
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     */
    public boolean getExtendedKeyUsageCritical() {
        return ((Boolean) data.get(EXTENDEDKEYUSAGECRITICAL)).booleanValue();
    }

    /*
     * Extended Key Usage is an arraylist of constant Integers.
     */
    public void setExtendedKeyUsage(ArrayList extendedkeyusage) {
        data.put(EXTENDEDKEYUSAGE, extendedkeyusage);
    }

    /*
     * Extended Key Usage is an arraylist of constant Integers.
     */
    public ArrayList getExtendedKeyUsage() {
        return (ArrayList) data.get(EXTENDEDKEYUSAGE);
    }

    /*
     * Returns an ArrayList of OID.strings defined in constant EXTENDEDKEYUSAGEOIDSTRINGS.
     */
    public ArrayList getExtendedKeyUsageAsOIDStrings() {
        ArrayList returnval = new ArrayList();
        ArrayList eku = (ArrayList) data.get(EXTENDEDKEYUSAGE);
        Iterator i = eku.iterator();

        while (i.hasNext()) {
            returnval.add(EXTENDEDKEYUSAGEOIDSTRINGS[((Integer) i.next()).intValue()]);
        }

        return returnval;
    }

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CloneNotSupportedException DOCUMENT ME!
     */
    public Object clone() throws CloneNotSupportedException {
        CertificateProfile clone = new CertificateProfile();
        HashMap clonedata = (HashMap) clone.saveData();

        Iterator i = (data.keySet()).iterator();

        while (i.hasNext()) {
            Object key = i.next();
            clonedata.put(key, data.get(key));
        }

        clone.loadData(clonedata);

        return clone;
    }

    /**
     * Implemtation of UpgradableDataHashMap function getLatestVersion
     *
     * @return DOCUMENT ME!
     */
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /**
     * Implemtation of UpgradableDataHashMap function upgrade.
     */
    public void upgrade() {
        if (LATEST_VERSION != getVersion()) {
            // New version of the class, upgrade
            data.put(VERSION, new Float(LATEST_VERSION));

            if (data.get(ALLOWKEYUSAGEOVERRIDE) == null) {
                data.put(ALLOWKEYUSAGEOVERRIDE, Boolean.TRUE);
            }

            if (data.get(USEEXTENDEDKEYUSAGE) == null) {
                data.put(USEEXTENDEDKEYUSAGE, Boolean.FALSE);
            }

            if (data.get(EXTENDEDKEYUSAGE) == null) {
                data.put(EXTENDEDKEYUSAGE, new ArrayList());
            }

            if (data.get(EXTENDEDKEYUSAGECRITICAL) == null) {
                data.put(EXTENDEDKEYUSAGECRITICAL, Boolean.FALSE);
            }
        }
    }
}
