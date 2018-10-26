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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.TreeSet;

/**
 * Builder helper of the MultiGroupPublisher for test cases.
 *
 * @version $Id: MultiGroupPublisherBuilder.java 30234 2018-10-26 15:51:27Z andrey_s_helmes $
 */
public class MultiGroupPublisherBuilder {

    private String description;
    private boolean keepPublishedInQueue;
    private String name;
    private boolean onlyUseQueue;
    private List<TreeSet<Integer>> publisherGroups;
    private boolean useQueueForCertificates;
    private boolean useQueueForCRLs;

    /**
     * Returns a builder instance for this class.
     *
     * @return an instance of builder for this class.
     */
    public static MultiGroupPublisherBuilder builder() {
        return new MultiGroupPublisherBuilder();
    }

    /**
     * Sets the description.
     *
     * @param description description.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder description(final String description) {
        this.description = description;
        return this;
    }

    /**
     * Sets the 'Keep published in queue' flag.
     *
     * @param keepPublishedInQueue 'Keep published in queue' flag.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder keepPublishedInQueue(final boolean keepPublishedInQueue) {
        this.keepPublishedInQueue = keepPublishedInQueue;
        return this;
    }

    /**
     * Sets the name.
     *
     * @param name name.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder name(final String name) {
        this.name = name;
        return this;
    }

    /**
     * Sets the 'Only use in queue' flag.
     *
     * @param onlyUseQueue 'Only use in queue' flag.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder onlyUseQueue(final boolean onlyUseQueue) {
        this.onlyUseQueue = onlyUseQueue;
        return this;
    }

    /**
     * Sets the list of sets containing publisher ids.
     *
     * @param publisherGroups the list of sets containing publisher ids.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder publisherGroups(final List<TreeSet<Integer>> publisherGroups) {
        this.publisherGroups = publisherGroups;
        return this;
    }

    /**
     * Sets the 'Use queue for certificates' flag.
     *
     * @param useQueueForCertificates 'Use queue for certificates' flag.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder useQueueForCertificates(final boolean useQueueForCertificates) {
        this.useQueueForCertificates = useQueueForCertificates;
        return this;
    }

    /**
     * Sets the 'Use queue for CRLs' flag.
     *
     * @param useQueueForCRLs 'Use queue for CRLs' flag.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder useQueueForCRLs(final boolean useQueueForCRLs) {
        this.useQueueForCRLs = useQueueForCRLs;
        return this;
    }

    /**
     * Sets the flags 'Keep published in queue', 'Only use in queue', 'Use queue for certificates' and 'Use queue for CRLs' to true.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder withAllFlagsToTrue() {
        return this
                .keepPublishedInQueue(true)
                .onlyUseQueue(true)
                .useQueueForCertificates(true)
                .useQueueForCRLs(true);
    }

    /**
     * Sets the flags 'Keep published in queue', 'Only use in queue', 'Use queue for certificates' and 'Use queue for CRLs' to false.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder withAllFlagsToFalse() {
        return this
                .keepPublishedInQueue(false)
                .onlyUseQueue(false)
                .useQueueForCertificates(false)
                .useQueueForCRLs(false);
    }

    /**
     * Adds a new publisher group to the end as a TreeSet represented by input collection.
     *
     * @param publisherIds a collection of publisher ids to add as a single set.
     *
     * @return instance of this builder.
     */
    public MultiGroupPublisherBuilder addPublisherGroup(final Collection<Integer> publisherIds) {
        if(publisherGroups == null) {
            publisherGroups = new ArrayList<>();
        }
        publisherGroups.add(new TreeSet<>(publisherIds));
        return this;
    }

    /**
     * Builds an instance of MultiGroupPublisher using this builder.
     *
     * @return instance of MultiGroupPublisher within this builder.
     */
    public MultiGroupPublisher build() {
        final MultiGroupPublisher multiGroupPublisher = new MultiGroupPublisher();
        multiGroupPublisher.setDescription(description);
        multiGroupPublisher.setKeepPublishedInQueue(keepPublishedInQueue);
        multiGroupPublisher.setName(name);
        multiGroupPublisher.setOnlyUseQueue(onlyUseQueue);
        multiGroupPublisher.setPublisherGroups(publisherGroups);
        multiGroupPublisher.setUseQueueForCertificates(useQueueForCertificates);
        multiGroupPublisher.setUseQueueForCRLs(useQueueForCRLs);
        return multiGroupPublisher;
    }
}
