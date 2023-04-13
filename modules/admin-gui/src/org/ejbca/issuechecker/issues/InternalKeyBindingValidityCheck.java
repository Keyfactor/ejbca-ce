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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.apache.log4j.Level;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingRules;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.ejbca.issuechecker.ConfigurationIssue;
import org.ejbca.issuechecker.Ticket;
import org.ejbca.issuechecker.TicketDescription;

import com.keyfactor.util.CertTools;

/**
 * Produce an error for each active internal key binding with an expired certificate.
 *
 * <p>Tickets created by this issue can be viewed by anyone who has view access to internal key bindings.
 *
 * @version $Id $
 */
public class InternalKeyBindingValidityCheck extends ConfigurationIssue {
    private final InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    private final CertificateStoreSessionLocal certificateSession;
    private final AuthorizationSessionLocal authorizationSession;

    private final class InternalKeyBindingEntry {
        private final InternalKeyBinding internalKeyBinding;
        private final Optional<X509Certificate> x509Certificate;

        public InternalKeyBindingEntry(final InternalKeyBinding internalKeyBinding, final Optional<X509Certificate> x509Certificate) {
            this.internalKeyBinding = internalKeyBinding;
            this.x509Certificate = x509Certificate;
        }

        public InternalKeyBinding getInternalKeyBinding() {
            return internalKeyBinding;
        }

        public Optional<X509Certificate> getX509Certificate() {
            return x509Certificate;
        }
    }

    public InternalKeyBindingValidityCheck(final InternalKeyBindingDataSessionLocal internalKeyBindingDataSession,
            final CertificateStoreSessionLocal certificateSession, final AuthorizationSessionLocal authorizationSession) {
        this.internalKeyBindingDataSession = internalKeyBindingDataSession;
        this.certificateSession = certificateSession;
        this.authorizationSession = authorizationSession;
    }

    @Override
    public Level getLevel() {
        return Level.ERROR;
    }

    @Override
    public String getDescriptionLanguageKey() {
        return "INTERNAL_KEY_BINDING_VALIDITY_CHECK_ISSUE_DESCRIPTION";
    }

    @Override
    public String getDatabaseValue() {
        return "InternalKeyBindingValidityCheck";
    }

    @Override
    public List<Ticket> getTickets() {
        return internalKeyBindingDataSession.getIds(/* all types */ null)
                .stream()
                .map(id -> internalKeyBindingDataSession.getInternalKeyBinding(id))
                .filter(internalKeyBinding -> internalKeyBinding.getStatus() == InternalKeyBindingStatus.ACTIVE)
                .map(internalKeyBinding -> new InternalKeyBindingEntry(internalKeyBinding, getCertificate(internalKeyBinding)))
                .filter(entry -> entry.getX509Certificate().isPresent())
                .filter(entry -> !CertTools.isCertificateValid(entry.getX509Certificate().get(), false, 0))
                .map(entry -> Ticket
                        .builder(this, TicketDescription.fromResource(
                                "INTERNAL_KEY_BINDING_VALIDITY_CHECK_TICKET_DESCRIPTION",
                                entry.getInternalKeyBinding().getName()
                        ))
                        .withAccessControl(createAccessControlRule(entry.getInternalKeyBinding().getId()))
                        .build())
                .collect(Collectors.toList());
    }

    private Predicate<AuthenticationToken> createAccessControlRule(final int internalKeyBindingId) {
        return authenticationToken -> authorizationSession.isAuthorizedNoLogging(authenticationToken,
                InternalKeyBindingRules.VIEW.resource() + "/" + internalKeyBindingId);
    }

    private Optional<X509Certificate> getCertificate(final InternalKeyBinding internalKeyBinding) {
        if (internalKeyBinding.getCertificateId() == null) {
            return Optional.empty();
        }
        final CertificateDataWrapper certificateWrapper = certificateSession.getCertificateData(internalKeyBinding.getCertificateId());
        if (certificateWrapper == null) {
            return Optional.empty();
        }
        return Optional.of((X509Certificate) certificateWrapper.getCertificate());
    }
}
