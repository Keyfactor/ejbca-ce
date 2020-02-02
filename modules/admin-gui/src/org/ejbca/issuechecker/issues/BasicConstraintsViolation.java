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

package org.ejbca.issuechecker.issues;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map.Entry;
import java.util.stream.Collectors;

import org.apache.log4j.Level;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

/**
 * Produce an error for each X.509 CA with a certificate chain violating a basic constraint.
 *
 * <p>Tickets created by this issue can be viewed by anyone who is authorized to the CA.
 *
 * @version $Id$
 */
public class BasicConstraintsViolation extends ConfigurationIssue {
    private final class CaEntry {
        final Entry<Integer, String> idAndName;
        final CAInfo caInfo;

        public CaEntry(final Entry<Integer, String> idAndName, final CAInfo caInfo) {
            this.idAndName = idAndName;
            this.caInfo = caInfo;
        }

        public CAInfo getCaInfo() {
            return caInfo;
        }

        public int getCaId() {
            return idAndName.getKey();
        }

        public String getCaName() {
            return idAndName.getValue();
        }
    }

    private final CaSessionLocal caSession;

    public BasicConstraintsViolation(final CaSessionLocal caSession) {
        this.caSession = caSession;
    }

    @Override
    public Level getLevel() {
        return Level.ERROR;
    }

    @Override
    public String getDescriptionLanguageKey() {
        return "BASIC_CONSTRAINTS_VIOLATION_ISSUE_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "BasicConstraintsViolation";
    }

    @Override
    public List<Ticket> getTickets() {
        return caSession.getCAIdToNameMap()
            .entrySet()
            .stream()
            .map(idAndName -> new CaEntry(idAndName, caSession.getCAInfoInternal(idAndName.getKey())))
            .filter(caEntry -> caEntry.getCaInfo().getCAType() == CAInfo.CATYPE_X509)
            .filter(caEntry -> isViolatingBasicConstraint(convertToX509CertificateChain(caEntry.getCaInfo().getCertificateChain())))
            .map(caEntry -> Ticket
                    .builder(this, TicketDescription.fromResource("BASIC_CONSTRAINTS_VIOLATION_TICKET_DESCRIPTION", caEntry.getCaName()))
                    .withAccessControl(authenticationToken -> caSession.authorizedToCA(authenticationToken, caEntry.getCaId()))
                    .build())
            .collect(Collectors.toList());
    }

    private List<X509Certificate> convertToX509CertificateChain(List<Certificate> certificateChain) {
        return certificateChain == null ? Collections.emptyList()
                : certificateChain.stream().map(c -> X509Certificate.class.cast(c)).collect(Collectors.toList());
    }

    /**
     * Checks if a certificate in a certificate chain violates a basic constraint.
     * 
     * <p>A basic constraint is <i>not</i> violated if any of the following is true:
     * <ol>
     *      <li>The certificate chain is empty.</li>
     *      <li>All certificates contains the basic constraints extension, are CA certificates and adhere to any path length constraints imposed on them. 
     * </ol>
     * 
     * <p>Conversely, a basic constraint <i>is</i> violated if the following is true:
     * <ol>
     *      <li>At least one certificate in the chain is lacking the basic constraints extension, is not a CA certificate or violates a path length constraint.</li>
     * </ol>
     * 
     * @param certificateChain a certificate chain with the root CA certificate in last position, never null.
     * @return true if a basic constraint is violated and the CA certificate chain should be considered invalid, false otherwise.
     */
    protected boolean isViolatingBasicConstraint(final List<X509Certificate> certificateChain) {
        // Process the chain in reverse order, i.e. starting with the root
        for (int currentCertificateChainDepth = certificateChain.size() - 1; currentCertificateChainDepth >= 0; currentCertificateChainDepth--) {
            final X509Certificate certificate = certificateChain.get(currentCertificateChainDepth);
            final int pathLengthConstraint = certificate.getBasicConstraints();
            if (currentCertificateChainDepth > pathLengthConstraint) {
                return true;
            }
        }
        return false;
    }
}
