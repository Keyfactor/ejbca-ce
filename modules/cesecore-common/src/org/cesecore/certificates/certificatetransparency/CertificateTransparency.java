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
package org.cesecore.certificates.certificatetransparency;

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.cesecore.certificates.certificateprofile.CertificateProfile;

/**
 * X509CA will attempt to load org.cesecore.certificates.certificatetransparency.CertificateTransparencyImpl
 * that must implement this interface if it exists.
 * 
 * The reason why this is an interface is because the CT support is a separate feature not
 * included in standard EJBCA.
 * 
 * @version $Id$
 */
public interface CertificateTransparency {

    String SCTLIST_OID = "1.3.6.1.4.1.11129.2.4.2";
    
    byte[] fetchSCTList(List<Certificate> chain, CertificateProfile certProfile, Map<Integer,CTLogInfo> configuredCTLogs) throws CTLogException;
    byte[] fetchSCTList(List<Certificate> chain, CertificateProfile certProfile, Map<Integer,CTLogInfo> configuredCTLogs, boolean allLogs) throws CTLogException;
    byte[] fetchSCTList(List<Certificate> chain, Collection<CTLogInfo> ctlogs, int minSCTs, int maxSCTs, int maxRetries) throws CTLogException;
    void addPreCertPoison(X509v3CertificateBuilder precertbuilder);
    boolean hasSCTs(Certificate cert) throws IOException;
    
}
