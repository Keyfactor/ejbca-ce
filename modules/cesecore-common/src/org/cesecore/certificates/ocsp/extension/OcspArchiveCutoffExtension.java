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

package org.cesecore.certificates.ocsp.extension;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.cesecore.keybind.InternalKeyBinding;

import com.keyfactor.util.CertTools;

/**
 * Represents the OCSP Archive Cutoff extension described in RFC6960, section 4.4.4.
 * 
 * <blockquote>
 *  An OCSP responder MAY choose to retain revocation information beyond
 *  a certificate's expiration.  The date obtained by subtracting this
 *  retention interval value from the producedAt time in a response is
 *  defined as the certificate's "archive cutoff" date.
 *  <p>
 *  OCSP-enabled applications would use an OCSP archive cutoff date to
 *  contribute to a proof that a digital signature was (or was not)
 *  reliable on the date it was produced even if the certificate needed
 *  to validate the signature has long since expired.
 *  <p>
 *  OCSP servers that provide support for such a historical reference
 *  SHOULD include an archive cutoff date extension in responses.  If
 *  included, this value SHALL be provided as an OCSP singleExtensions
 *  extension identified by id-pkix-ocsp-archive-cutoff and of syntax
 *  GeneralizedTime.
 *  <p>
 *    <code>id-pkix-ocsp-archive-cutoff OBJECT IDENTIFIER ::= {id-pkix-ocsp 6}</code>
 *    <br/>
 *    <code>ArchiveCutoff ::= GeneralizedTime</code>
 *  <p>
 *  To illustrate, if a server is operated with a 7-year retention
 *  interval policy and status was produced at time t1, then the value
 *  for ArchiveCutoff in the response would be (t1 - 7 years).
 * </blockquote>
 * 
 * It is also used in ETSI EN 319 411-2 as follows:
 * <blockquote>
 *    CSS-6.3.10-08 [CONDITIONAL]: If OCSP is provided, the OCSP responder should use
 *    the ArchiveCutOff extension as specified in IETF RFC 6960 [i.9], with the archiveCutOff 
 *    date set to the CA's certificate "valid from" date.
 * </blockquote>
 * 
 * This extension was enabled in ocsp.properties by setting the property <code>ocsp.expiredcert.retentionperiod</code>.
 * As of EJBCA 7.3, it is instead enabled per OCSP key binding, and can be configured to use either a specified retention
 * period or the <code>notBefore</code> date of the issuer.
 * 
 * @version $Id$
 */
public class OcspArchiveCutoffExtension implements OCSPExtension {
    private static final Logger log = Logger.getLogger(OcspArchiveCutoffExtension.class);
    public static final String EXTENSION_NAME = "Archive Cutoff";

    @Override
    public void init() {
    }

    @Override
    public Map<ASN1ObjectIdentifier, Extension> process(final X509Certificate[] requestCertificates, final String remoteAddress, final String remoteHost,
            final X509Certificate cert, final CertificateStatus status, final InternalKeyBinding internalKeyBinding) {
        if (log.isDebugEnabled()) {
            log.debug(remoteAddress + " sent an OCSP request containing an OCSP archive cutoff extension, asking for the status of the certificate"
                    + " with serial number " + CertTools.getSerialNumberAsString(cert) + " issued by '" + CertTools.getIssuerDN(cert)  + "'. The OCSP archive cutoff extension"
                    + " should only be present in OCSP responses. This message is probably an indication of a misconfigured OCSP client.");
        }
        return new HashMap<>();
    }

    @Override
    public int getLastErrorCode() {
        return 0;
    }

    @Override
    public Set<OCSPExtensionType> getExtensionType() {
        final HashSet<OCSPExtensionType> applicableExtensionTypes = new HashSet<>();
        applicableExtensionTypes.add(OCSPExtensionType.SINGLE_RESPONSE);
        return applicableExtensionTypes;
    }

    @Override
    public String getOid() {
        return OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId();
    }

    @Override
    public String getName() {
        return EXTENSION_NAME;
    }
}
