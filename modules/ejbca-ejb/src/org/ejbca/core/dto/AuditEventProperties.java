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
package org.ejbca.core.dto;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;

import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Container class having flat structure for building Map (Map&lt;String, Object&gt;). Supports additional details
 * construction for Audit Log.
 * <br/><br/>
 * Supported attributes of an event are:
 * <ul>
 *     <li>certSignKey;</li>
 *     <li>crlSignKey;</li>
 *     <li>error;</li>
 *     <li>msg;</li>
 *     <li>oldproperties;</li>
 *     <li>oldsequence;</li>
 *     <li>properties;</li>
 *     <li>sequence.</li>
 * </ul>
 * The construction of resulting map uses non null attributes.
 * <br/><br/>
 * <h3>Example 1:</h3>
 * <pre>
 *     AuditEventProperties.builder().withMsg("My message").build().toMap();
 *     // Resulting Map
 *     Map<String, Object> details = new LinkedHashMap<>();
 *     details.put("msg", "My message");
 * </pre>
 * <br/>
 * <h3>Example 2:</h3>
 * <pre>
 *     AuditEventProperties.builder()
 *         .withMsg("My message")
 *         .withOldsequence("old sequence")
 *         .withSequence("key sequence")
 *         .build()
 *     // Resulting Map
 *     Map<String, Object> details = new LinkedHashMap<>();
 *     details.put("msg", "My message");
 *     details.put("oldsequence", "old sequence");
 *     details.put("sequence", "key sequence");
 * </pre>
 * @see org.cesecore.audit.log.SecurityEventsLoggerSession#log(AuthenticationToken, EventType, EventStatus, ModuleType, ServiceType, String, String, String, Map)
 * @version $Id$
 */
public class AuditEventProperties {

    private final String certSignKey;
    private final String crlSignKey;
    private final String error;
    private final String msg;
    private final Properties oldproperties;
    private final String oldsequence;
    private final Properties properties;
    private final String sequence;

    // Private constructor, use builder
    private AuditEventProperties(
            final String certSignKey,
            final String crlSignKey,
            final String error,
            final String msg,
            final Properties oldproperties,
            final String oldsequence,
            final Properties properties,
            final String sequence
    ) {
        this.certSignKey = certSignKey;
        this.crlSignKey = crlSignKey;
        this.error = error;
        this.msg = msg;
        this.oldproperties = oldproperties;
        this.oldsequence = oldsequence;
        this.properties = properties;
        this.sequence = sequence;
    }

    /**
     * Returns the builder instance of this class.
     * @return AuditEventPropertiesBuilder
     */
    public static AuditEventPropertiesBuilder builder() {
        return new AuditEventPropertiesBuilder();
    }

    /**
     * Transforms the flat structure of non null attributes into Map&lt;String, Object&gt;.
     * @return The map of non null attributes.
     */
    public Map<String, Object> toMap() {
        final Map<String, Object> map = new LinkedHashMap<>();
        if(certSignKey != null) {
            map.put("certSignKey", certSignKey);
        }
        if(crlSignKey != null) {
            map.put("crlSignKey", crlSignKey);
        }
        if(error != null) {
            map.put("error", error);
        }
        if(msg != null) {
            map.put("msg", msg);
        }
        if(oldproperties != null) {
            map.put("oldproperties", oldproperties);
        }
        if(oldsequence != null) {
            map.put("oldsequence", oldsequence);
        }
        if(properties != null) {
            map.put("properties", properties);
        }
        if(sequence != null) {
            map.put("sequence", sequence);
        }
        return map;
    }

    /**
     * Builder.
     */
    public static class AuditEventPropertiesBuilder {

        private String certSignKey;
        private String crlSignKey;
        private String error;
        private String msg;
        private Properties oldproperties;
        private String oldsequence;
        private Properties properties;
        private String sequence;

        private AuditEventPropertiesBuilder() {
        }

        public AuditEventPropertiesBuilder withCertSignKey(final String certSignKey) {
            this.certSignKey = certSignKey;
            return this;
        }

        public AuditEventPropertiesBuilder withCrlSignKey(final String crlSignKey) {
            this.crlSignKey = crlSignKey;
            return this;
        }

        public AuditEventPropertiesBuilder withError(final String error) {
            this.error = error;
            return this;
        }

        public AuditEventPropertiesBuilder withMsg(final String msg) {
            this.msg = msg;
            return this;
        }

        public AuditEventPropertiesBuilder withOldproperties(final Properties oldproperties) {
            this.oldproperties = oldproperties;
            return this;
        }

        public AuditEventPropertiesBuilder withOldsequence(final String oldsequence) {
            this.oldsequence = oldsequence;
            return this;
        }

        public AuditEventPropertiesBuilder withProperties(final Properties properties) {
            this.properties = properties;
            return this;
        }

        public AuditEventPropertiesBuilder withSequence(final String sequence) {
            this.sequence = sequence;
            return this;
        }

        public AuditEventProperties build() {
            return new AuditEventProperties(certSignKey, crlSignKey, error, msg, oldproperties, oldsequence, properties, sequence);
        }
    }
}
