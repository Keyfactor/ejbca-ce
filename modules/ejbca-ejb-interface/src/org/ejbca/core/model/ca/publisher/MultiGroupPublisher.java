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
package org.ejbca.core.model.ca.publisher;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeSet;
import java.util.concurrent.ThreadLocalRandom;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.model.util.EjbLocalHelper;

/**
 * Publishes to multiple groups of publishers. For each group it publishes to one random publisher.
 * <p>
 * Useful when you have a lot of publishers, and you want to manage them in a single place.
 * @version $Id$
 */
public class MultiGroupPublisher extends BasePublisher {

    private static final Logger log = Logger.getLogger(MultiGroupPublisher.class);

    private static final long serialVersionUID = 1L;

    private static final float LATEST_VERSION = 1.0F;
    private static final String PROPERTYKEY_PUBLISHERGROUPS = "publishergroups";

    private transient PublisherSessionLocal cachedPublisherSession;

    public MultiGroupPublisher() {
        super();
        data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_MULTIGROUPPUBLISHER));
        data.put(PROPERTYKEY_PUBLISHERGROUPS, new ArrayList<>());
    }

    @SuppressWarnings("unchecked")
    public List<TreeSet<Integer>> getPublisherGroups() {
        final Object value = data.get(PROPERTYKEY_PUBLISHERGROUPS);
        return value != null ? (List<TreeSet<Integer>>) value : new ArrayList<TreeSet<Integer>>();
    }

    public void setPublisherGroups(final List<TreeSet<Integer>> publisherGroups) {
        data.put(PROPERTYKEY_PUBLISHERGROUPS, new ArrayList<>(publisherGroups));
    }


    private PublisherSessionLocal getPublisherSession() {
        if (cachedPublisherSession == null) {
            cachedPublisherSession = new EjbLocalHelper().getPublisherSession();
        }
        return cachedPublisherSession;
    }

    private BasePublisher getPublisher(int publisherId) {
        return getPublisherSession().getPublisher(publisherId);
    }

    /**
     * Returns a list of publishers to use for some certificate or CRL.
     * The result is randomized, so it will return a different result each time.
     * This method uses the PublisherCache for better performance.
     * @param getAll Return ALL publishers in each group, instead of only a random one.
     * @return List of publishers to use.
     */
    private List<BasePublisher> getPublishersToUse(final boolean getAll) {
        final List<BasePublisher> publishers = new ArrayList<>();
        for (final TreeSet<Integer> group : getPublisherGroups()) {
            if (getAll) {
                for (int publisherId : group) {
                    final BasePublisher publisher = getPublisher(publisherId);
                    if (publisher != null) {
                        publishers.add(publisher);
                    } else if (log.isDebugEnabled()) {
                        log.debug("Ignoring non-existent publisher: " + publisherId);
                    }
                }
            } else {
                final List<Integer> ids = new ArrayList<>(group);
                while (!ids.isEmpty()) {
                    // Grab a random publisher
                    final int index = ThreadLocalRandom.current().nextInt(ids.size());
                    final int publisherId = ids.get(index);
                    final BasePublisher publisher = getPublisher(publisherId);
                    if (publisher != null) {
                        publishers.add(publisher);
                        break;
                    } else {
                        // This happens when clicking "Test Connection", so it won't spam the logs
                        log.warn("Ignoring non-existent publisher " + publisherId + " in publisher " + getName());
                    }
                    ids.remove(index);
                }
            }
        }
        return publishers;
    }


    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        // Checking the randomized publishers here would introduce a race condition, so we don't do that
        final boolean empty = getPublisherGroups().isEmpty();
        if (empty && log.isDebugEnabled()) {
            log.debug("No publishers configured in multi group publisher '" + getName() + "'.");
        }
        return !empty;
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        throw new UnsupportedOperationException("Legacy storeCertificate method should never have been invoked for this publisher.");
    }

    @Override
    public boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData) throws PublisherException {
        throw new UnsupportedOperationException("Internal error. Wrong storeCertificate method was called.");
    }

    @Override
    public boolean storeCertificate(final AuthenticationToken authenticationToken, final CertificateData certificateData, final Base64CertData base64CertData, final String password, final String userDN, final ExtendedInformation extendedinformation) throws PublisherException {
        log.trace(">storeCertificate");
        final List<Integer> publisherIdsToUse = new ArrayList<>();
        for (final BasePublisher publisher : getPublishersToUse(false)) {
            if (log.isDebugEnabled()) {
                log.debug("Will publish certificate " + certificateData.getSerialNumberHex() + " to publisher '" + publisher.getName() + "'");
            }
            publisherIdsToUse.add(publisher.getPublisherId());
        }
        if (publisherIdsToUse.isEmpty()) {
            log.info("No publishers available in multi group publisher '" + getName() + "'. Can't publish certificate " + certificateData.getSerialNumberHex());
            return false;
        }
        try {
            getPublisherSession().storeCertificate(authenticationToken, publisherIdsToUse, new CertificateDataWrapper(null, certificateData, base64CertData), password, userDN, extendedinformation);
        } catch (AuthorizationDeniedException e) {
            throw new PublisherException("Authorization was denied: " + e.getMessage());
        }
        log.trace("<storeCertificate");
        return true;
    }

    @Override
    public boolean isFullEntityPublishingSupported() {
        return true;
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        final List<Integer> publisherIdsToUse = new ArrayList<>();
        log.trace(">storeCRL");
        for (final BasePublisher publisher : getPublishersToUse(false)) {
            if (log.isDebugEnabled()) {
                log.debug("Will publish CRL " + number + " for CA " + cafp + " to publisher '" + publisher.getName() + "'");
            }
            publisherIdsToUse.add(publisher.getPublisherId());
        }
        if (publisherIdsToUse.isEmpty()) {
            log.info("No publishers available in multi group publisher '" + getName() + "'. Can't publish CRL " + number + " for CA " + cafp);
            return false;
        }
        try {
            getPublisherSession().storeCRL(admin, publisherIdsToUse, incrl, cafp, number, userDN);
        } catch (AuthorizationDeniedException e) {
            throw new PublisherException("Authorization was denied: " + e.getMessage());
        }
        log.trace("<storeCRL");
        return true;
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        Exception publisherException = null;
        List<String> failedNames = new ArrayList<>();
        log.debug("Testing all publishers in multi group publisher.");
        for (final BasePublisher publisher : getPublishersToUse(true)) {
            if (log.isDebugEnabled()) {
                log.debug("Testing publisher: " + publisher.getName());
            }
            try {
                publisher.testConnection();
            } catch (PublisherConnectionException | RuntimeException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Publisher '" + publisher.getName() + "' failed: " + e.getMessage(), e);
                }
                failedNames.add(publisher.getName());
                if (publisherException == null) {
                    publisherException = e;
                }
            }
        }
        log.debug("Done testing publishers in multi group publisher.");
        if (publisherException != null) {
            final String msg = "Publishers [" + String.join(", ", failedNames) + "] failed. First failure: " +publisherException.getMessage();
            log.info(msg, publisherException);
            throw new PublisherConnectionException(msg, publisherException);
        }
    }

    @Override
    public Object clone() throws CloneNotSupportedException {
        // TODO see LdapPublisher.clone()
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    /** 
     * Implemtation of UpgradableDataHashMap function upgrade. 
     */
    @Override
    public void upgrade() {
        log.trace(">upgrade");
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // Does nothing currently
            data.put(VERSION, new Float(LATEST_VERSION));
        }
        log.trace("<upgrade");
    }

}
