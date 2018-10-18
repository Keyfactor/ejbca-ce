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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.endentity.ExtendedInformation;

/**
 * Publishes to multiple groups of publishers. For each group it publishes to one random publisher.
 * <p>
 * Useful when you have a lot of publishers, and you want to manage them in a single place.
 * @version $Id$
 */
public class MultiGroupPublisher extends BasePublisher {

    private static final long serialVersionUID = 1L;

    private static final float LATEST_VERSION = 1.0F;
    private static final String PROPERTYKEY_PUBLISHERGROUPS = "publishergroups";
    
//    private transient PublisherSessionLocal cachedPublisherSession;

    public MultiGroupPublisher() {
        super();
        data.put(TYPE, Integer.valueOf(PublisherConst.TYPE_LDAPPUBLISHER));
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


//    private PublisherSessionLocal getPublisherSession() {
//        if (cachedPublisherSession != null) {
//            cachedPublisherSession = new EjbLocalHelper().getPublisherSession();
//        }
//        return cachedPublisherSession;
//    }
//
//    private BasePublisher getPublisher(int publisherId) {
//        return getPublisherSession().getPublisher(publisherId);
//    }


    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        // Checking the randomized publishers here would introduce a race condition, so we don't do that
        return !getPublisherGroups().isEmpty();
    }

    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp,
            int status, int type, long revocationDate, int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws PublisherException {
        // TODO Choose a random publisher ID in each group. Then publish to each of those publishers
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        // TODO Choose a random publisher ID in each group. Then publish to each of those publishers
        throw new UnsupportedOperationException("Not implemented");
    }

    @Override
    public void testConnection() throws PublisherConnectionException {
        // TODO Call testConnection on all publishers
        throw new UnsupportedOperationException("Not implemented");
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

}
