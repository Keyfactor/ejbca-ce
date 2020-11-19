/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.msae;

import java.util.Map;
import java.util.TreeMap;

/**
 * Provides strings for OIDs that appear in PKCS10 requests from Windows enrollment clients.
 * Used by ASN1.dump method.
 *
 */
public class OidMap
{
    static String getOidName(String oid) {
        return oidMap.get(oid);
    }

    /**
     * TODO Is this initialization thread-safe?
     * And is this an efficient type of map to use?
     */
    static final Map<String, String> oidMap = new TreeMap<String, String>();

    static
    {
        /**
         * TODO Normalize spelling below.
         */
        oidMap.put("1.2.840.113549.1.1.1", "RSA encryption");
        oidMap.put("1.2.840.113549.1.1.5", "SHA-1 with RSA Encryption");

        oidMap.put("1.2.840.113549.1.9.14", "PKCS#9 ExtensionRequest");
        oidMap.put("1.2.840.113549.1.9.15", "S/Mime capabilities");

        oidMap.put("1.2.840.113549.3.2", "RC2 in CBC mode. ");
        oidMap.put("1.2.840.113549.3.4", "RSA RC4 private key encryption algorithm without MAC");
        oidMap.put("1.2.840.113549.3.7", "DES encryption in CBC mode");

        oidMap.put("1.3.6.1.4.1.311.20.2", "Certificate Template Name Domain Controller");  // MS ?

        // http://support.microsoft.com/kb/287547
        oidMap.put("1.3.6.1.4.1.311.21.7", "Certificate Template");   // MS
        oidMap.put("1.3.6.1.4.1.311.21.10", "Application Policies extension");    // MS

        // Extended Key Usage
        oidMap.put("1.3.6.1.5.5.7.3.1", "Server Authentication");
        oidMap.put("1.3.6.1.5.5.7.3.2", "Client Authentication");
        oidMap.put("1.3.6.1.5.5.7.3.3", "Code Signing");
        oidMap.put("1.3.6.1.5.5.7.3.4", "Secure Email");    // Email Protection
        oidMap.put("1.3.6.1.5.5.7.3.5", "IP Security End System");
        oidMap.put("1.3.6.1.5.5.7.3.6", "IP Security Tunnel Termination");
        oidMap.put("1.3.6.1.5.5.7.3.7", "IP Security User");
        oidMap.put("1.3.6.1.5.5.7.3.8", "Time Stamping");
        oidMap.put("1.3.6.1.5.5.7.3.9", "OCSP Signing");

        // MS extended key usages?
        oidMap.put("1.3.6.1.4.1.311.10.3.1", "Microsoft Trust List Signing"); // Signer of CTLs/Microsoft Trust List Signing
        oidMap.put("1.3.6.1.4.1.311.10.3.2", "Signer of Time Stamps (MS)"); // Microsoft Time Stamping
        oidMap.put("1.3.6.1.4.1.311.10.3.3", "Server Gated Crypto");    // Can use strong encryption in export environment
        oidMap.put("1.3.6.1.4.1.311.10.3.3.1", "Serialized");    // Can use strong encryption in export environment
        oidMap.put("1.3.6.1.4.1.311.10.3.4", "Encrypting File System (EFS)");
        oidMap.put("1.3.6.1.4.1.311.10.3.4.1", "Microsoft EFS File Recovery");
        oidMap.put("1.3.6.1.4.1.311.10.3.5", "Windows Hardware Compatible (WHQL) Crypto");  // Windows Hardware Driver Verification
        oidMap.put("1.3.6.1.4.1.311.10.3.6", "NT5 Crypto"); // Windows System Component Verification
        oidMap.put("1.3.6.1.4.1.311.10.3.7", "OEM WHQL Crypto");    // OEM Windows System Component Verification
        oidMap.put("1.3.6.1.4.1.311.10.3.8", "Embedded NT Crypto"); // Embedded Windows System Component Verification
        oidMap.put("1.3.6.1.4.1.311.10.3.9", "Root List Signer");   // Signer of a CTL containing trusted roots
        oidMap.put("1.3.6.1.4.1.311.10.3.10", "KP Qualified Subordination");    // Can sign cross-cert and subordinate CA requests with qualified subordination (name constraints, policy mapping, etc.)
        oidMap.put("1.3.6.1.4.1.311.10.3.11", "KP Key Recovery");    // Can be used to encrypt/recover escrowed keys
        oidMap.put("1.3.6.1.4.1.311.10.3.12", "KP Document Signing");   // Signer of documents
        oidMap.put("1.3.6.1.4.1.311.10.3.13", "KP Lifetime Signing");   // Limits the valid lifetime of the signature to the lifetime of the certificate.
        oidMap.put("1.3.6.1.4.1.311.10.3.19", "Revoked List Signer");
        
        oidMap.put("1.3.6.1.4.1.311.10.5.1", "Digital Rights");   // Microsoft Music/DRM/Digital Rights
        oidMap.put("1.3.6.1.4.1.311.10.6.1", "Licenses");   // Microsoft Licenses/ Key Pack Licenses
        oidMap.put("1.3.6.1.4.1.311.10.6.2", "License Server");   // Microsoft Licenses/ License Server Verification
//        CryptUI                                    1.3.6.1.4.1.311.10.12
        oidMap.put("1.3.6.1.4.1.311.10.12.1", "All Application Policies");
//        Microsoft Enrollment Infrastructure..............1.3.6.1.4.1.311.20
        oidMap.put("1.3.6.1.4.1.311.20.1", "CTL Usage");    // Auto Enroll CTL Usage
        oidMap.put("1.3.6.1.4.1.311.20.2", "Enroll Certtype Extension");
        oidMap.put("1.3.6.1.4.1.311.20.2.1", "Certificate Request Agent");   // Enrollment Agent
        oidMap.put("1.3.6.1.4.1.311.20.2.2", "MS Smart Card Logon");
//        szOID_NT_PRINCIPAL_NAME                 1.3.6.1.4.1.311.20.2.3
//        szOID_CERT_MANIFOLD                     1.3.6.1.4.1.311.20.3
        oidMap.put("1.3.6.1.4.1.311.21", "Microsoft CertSrv Infrastructure");
        oidMap.put("1.3.6.1.4.1.311.21.5", "Private Key Archival");   // Enhanced Key Usage for CA encryption certificate/KP CA Exchange
        oidMap.put("1.3.6.1.4.1.311.21.6", "KP Key Recovery Agent");   // Enhanced Key Usage for key recovery agent certificate
        oidMap.put("1.3.6.1.4.1.311.21.19", "Directory Service Email Replication");   // Enhanced key usage for DS email replication
        oidMap.put("1.3.6.1.4.1.311.21.20", "Client Information");
        oidMap.put("1.3.6.1.4.1.311.44.3.4", "Peer to Peer Trust");  // PKI Peer Auth
        oidMap.put("1.3.6.1.4.1.311.61.1.1", "Kernel Mode Code Signing");
        oidMap.put("1.3.6.1.4.1.311.47.1.1", "System Health Authentication");
        oidMap.put("1.3.6.1.4.1.311.64.1.1", "DNS Server Trust");
        oidMap.put("1.3.6.1.4.1.311.67.1.1", "BitLocker Drive Encryption");
        oidMap.put("1.3.6.1.4.1.311.67.1.2", "BitLocker Data Recovery Agent");
        
        oidMap.put("1.3.6.1.5.2.3.5", "KDC Authentication");
        oidMap.put("1.3.6.1.5.5.8.2.2", "IP security IKE intermediate");

        oidMap.put("1.3.14.3.2.7", "desCBC");

        oidMap.put("2.5.4.3", "id-at-commonName");
        oidMap.put("2.5.4.43", "id-at-initials");

        oidMap.put("2.5.29.14", "SubjectKeyIdentifier");
        oidMap.put("2.5.29.15", "KeyUsage");
        oidMap.put("2.5.29.16", "PrivateKeyUsage");
        oidMap.put("2.5.29.17", "SubjectAlternativeName");
        oidMap.put("2.5.29.18", "IssuerAlternativeName");
        oidMap.put("2.5.29.19", "BasicConstraints");
        oidMap.put("2.5.29.30", "NameConstraints");
        oidMap.put("2.5.29.33", "PolicyMappings");
        oidMap.put("2.5.29.35", "AuthorityKeyIdentifier");
        oidMap.put("2.5.29.36", "PolicyConstraints");
        oidMap.put("2.5.29.37", "Extended key usage");
        oidMap.put("2.5.29.37.0", "Any Purpose");    // Any purpose/Any Extended key usage
    }

}
