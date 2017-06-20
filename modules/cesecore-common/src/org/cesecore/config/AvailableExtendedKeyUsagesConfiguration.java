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

package org.cesecore.config;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.cesecore.configuration.ConfigurationBase;

/**
 * This file handles configuration of Available Extended Key Usages
 * 
 * @version $Id$
 */
public class AvailableExtendedKeyUsagesConfiguration extends ConfigurationBase implements Serializable{

    private static final long serialVersionUID = -3430732247486886608L;
    public static final String CONFIGURATION_ID = "AVAILABLE_EXTENDED_KEY_USAGES";
    
    /** Creates a new instance of AvailableExtendedKeyUsagesConfiguration without defaults */
    public AvailableExtendedKeyUsagesConfiguration(boolean ignored)  {
        super();
    }

    /** Creates a new instance of AvailableExtendedKeyUsagesConfiguration */
    public AvailableExtendedKeyUsagesConfiguration()  {
       super();
       // Before EJBCA 6.4.0 this was configured in a property file
       addExtKeyUsage("2.5.29.37.0", "EKU_PKIX_ANYEXTENDEDKEYUSAGE");
       addExtKeyUsage("1.3.6.1.5.5.7.3.1", "EKU_PKIX_SERVERAUTH");
       addExtKeyUsage("1.3.6.1.5.5.7.3.2", "EKU_PKIX_CLIENTAUTH");
       addExtKeyUsage("1.3.6.1.5.5.7.3.3", "EKU_PKIX_CODESIGNING");
       addExtKeyUsage("1.3.6.1.5.5.7.3.4", "EKU_PKIX_EMAILPROTECTION");
       //addExtKeyUsage("1.3.6.1.5.5.7.3.5", "EKU_PKIX_IPSECENDSYSTEM");  // Deprecated EKU
       //addExtKeyUsage("1.3.6.1.5.5.7.3.6", "EKU_PKIX_IPSECTUNNEL");     // Deprecated EKU
       //addExtKeyUsage("1.3.6.1.5.5.7.3.7", "EKU_PKIX_IPSECUSER");       // Deprecated EKU
       addExtKeyUsage("1.3.6.1.5.5.7.3.8", "EKU_PKIX_TIMESTAMPING");
       addExtKeyUsage("1.3.6.1.5.5.7.3.9", "EKU_PKIX_OCSPSIGNING");
       // RFC 4334 - Certificate Extensions Supporting Authentication in PPP and WLAN
       addExtKeyUsage("1.3.6.1.5.5.7.3.13", "EKU_PKIX_EAPOVERPPP");
       addExtKeyUsage("1.3.6.1.5.5.7.3.14", "EKU_PKIX_EAPOVERLAN");
       // RFC 5055 - Server-Based Certificate Validation Protocol (SCVP)
       addExtKeyUsage("1.3.6.1.5.5.7.3.15", "EKU_PKIX_SCVPSERVER");
       addExtKeyUsage("1.3.6.1.5.5.7.3.16", "EKU_PKIX_SCVPCLIENT");
       // RFC 4945 - PKI Profile for IKE, ISAKMP and PKIX
       addExtKeyUsage("1.3.6.1.5.5.7.3.17", "EKU_PKIX_IPSECIKE");
       // RFC 5924 - Extended Key Usage (EKU) for Session Initiation Protocol (SIP) X.509 Certificates
       addExtKeyUsage("1.3.6.1.5.5.7.3.20", "EKU_PKIX_SIPDOMAIN");
       // RFC 6187 - X.509v3 Certificates for Secure Shell Authentication
       addExtKeyUsage("1.3.6.1.5.5.7.3.21", "EKU_PKIX_SSHCLIENT");
       addExtKeyUsage("1.3.6.1.5.5.7.3.22", "EKU_PKIX_SSHSERVER");
       // -- Microsoft extended key usages
       // Microsoft Smart card Logon (szOID_KP_SMARTCARD_LOGON)
       addExtKeyUsage("1.3.6.1.4.1.311.20.2.2", "EKU_MS_SMARTCARDLOGON");
       // Microsoft Document Signing (szOID_KP_DOCUMENT_SIGNING)
       addExtKeyUsage("1.3.6.1.4.1.311.10.3.12", "EKU_MS_DOCUMENTSIGNING");
       // Microsoft Individual Code Signing (SPC_INDIVIDUAL_SP_KEY_PURPOSE_OBJID)
       addExtKeyUsage("1.3.6.1.4.1.311.2.1.21", "EKU_MS_CODESIGNING_IND");
       // Microsoft Commercial Code Signing (SPC_COMMERCIAL_SP_KEY_PURPOSE_OBJID)
       addExtKeyUsage("1.3.6.1.4.1.311.2.1.22", "EKU_MS_CODESIGNING_COM");
       // Microsoft Encrypted File System (szOID_EFS_CRYPTO)
       addExtKeyUsage("1.3.6.1.4.1.311.10.3.4", "EKU_MS_EFSCRYPTO");
       // Microsoft Encrypted File System Recovery (szOID_EFS_RECOVERY)
       addExtKeyUsage("1.3.6.1.4.1.311.10.3.4.1", "EKU_MS_EFSRECOVERY");
       // -- Intel extended key usages
       // Intel AMT (out of band) network management
       addExtKeyUsage("2.16.840.1.113741.1.2.3", "EKU_INTEL_AMT");
       // -- ETSI (European Telecommunications Standards Institute) extended key usages
       // ETSI TS 102 231 TSL Signing (id-tsl-kp-tslSigning)
       addExtKeyUsage("0.4.0.2231.3.0", "EKU_ETSI_TSLSIGNING");
       // -- Adobe extended key usages
       // Adobe PDF Signing http://www.adobe.com/misc/pdfs/Adobe_CDS_CPv011604clean.pdf
       addExtKeyUsage("1.2.840.113583.1.1.5", "EKU_ADOBE_PDFSIGNING");
       // -- CSN (Czech technical standard) extended key usages
       // CSN 36 9791 TSL Client (id-csn-369791-tls-client)
       addExtKeyUsage("1.2.203.7064.1.1.369791.1", "EKU_CSN_TLSCLIENT");
       // CSN 36 9791 TSL Server (id-csn-369791-tls-server)
       addExtKeyUsage("1.2.203.7064.1.1.369791.2", "EKU_CSN_TLSSERVER");
       // -- Kerberos extended key usages
       // RFC 4556 - Kerberos PKINIT client (id-pkinit-KPClientAuth)
       addExtKeyUsage("1.3.6.1.5.2.3.4", "EKU_KRB_PKINIT_CLIENT");
       // RFC 4556 - Kerberos PKINIT server/KDC (id-pkinit-KPKdc)
       addExtKeyUsage("1.3.6.1.5.2.3.5", "EKU_KRB_PKINIT_KDC");
       // -- ICAO (International Civil Aviation Organization) extended key usages
       // ICAO Master List Signer (cscaMasterListSigningKey)
       // http://www.icao.int/Security/mrtd/PKD%20Documents/PKDTechnicalDocuments/GuidanceDocument-PKIforMachineReadableTravelDocuments.pdf
       addExtKeyUsage("2.23.136.1.1.3", "EKU_ICAO_MASTERLISTSIGNING");
       // -- NIST (National Institute of Standards and Technology) extended key usages
       // The id-PIV-cardAuth keyPurposeID specifies that the public key is used to authenticate the PIV-I card rather than the PIV-I card holder.
       // http://www.idmanagement.gov/sites/default/files/documents/pivi_certificate_crl_profile.pdf
       addExtKeyUsage("2.16.840.1.101.3.6.8", "EKU_NIST_PIVCARDAUTH");
    }

    public AvailableExtendedKeyUsagesConfiguration(Serializable dataobj) {
        @SuppressWarnings("unchecked")
        LinkedHashMap<Object, Object> d = (LinkedHashMap<Object, Object>) dataobj;
        data = d;
    }
    
    @Override
    public String getConfigurationId() {
        return CONFIGURATION_ID;
    }
    
    public boolean isExtendedKeyUsageSupported(String oid) {
        return data.containsKey(oid.trim());
    }
    
    public void addExtKeyUsage(String oid, String name) {
        data.put(oid.trim(), name);
    }
    
    public void removeExtKeyUsage(String oid) {
        data.remove(oid.trim());
    }
    
    public String getExtKeyUsageName(String oid) {
        oid = oid.trim();
        String name = (String) data.get(oid);
        if(name == null) {
            name = oid;
        }
        return name;
    }
    
    public List<String> getAllOIDs() {
        Set<Object> keyset = data.keySet();
        ArrayList<String> keys = new ArrayList<String>();
        for(Object k : keyset) {
            if(!StringUtils.equalsIgnoreCase((String) k, "version")) {
                keys.add( (String) k );
            }
        }
        return keys;
    }
    
    public Map<String, String> getAllEKUOidsAndNames() {
        @SuppressWarnings("unchecked")
        Map<String, String> ret = (Map<String, String>) saveData();
        ret.remove("version");
        return ret;
    }
    
    public Properties getAsProperties() {
        Properties properties = new Properties();
        Map<String, String> allEkus = getAllEKUOidsAndNames();
        for(Entry<String, String> eku : allEkus.entrySet()) {
            properties.setProperty(eku.getKey(), eku.getValue());
        }
        return properties;
    }
    
    @Override
    public void upgrade() {}
    
}
