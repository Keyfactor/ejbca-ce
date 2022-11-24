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
package org.cesecore.audit.log.dto;

import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.collections4.MapUtils;
import org.apache.log4j.Logger;
import org.cesecore.audit.enums.EventStatus;
import org.cesecore.audit.enums.EventType;
import org.cesecore.audit.enums.ModuleType;
import org.cesecore.audit.enums.ServiceType;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * Container class having flat structure for building Map (Map&lt;String, Object&gt;). Supports additional details
 * construction for Security Log.
 * <br/><br/>
 * Supported attributes of an event are:
 * <ul>
 *     <li>certSignKey - {@link #CERT_SIGN_KEY};</li>
 *     <li>crlSignKey - {@link #CRL_SIGN_KEY};</li>
 *     <li>error - {@link #ERROR};</li>
 *     <li>msg - {@link #MSG};</li>
 *     <li>oldproperties - {@link #OLD_PROPERTIES};</li>
 *     <li>oldsequence - {@link #OLD_SEQUENCE};</li>
 *     <li>properties - {@link #PROPERTIES};</li>
 *     <li>sequence - {@link #SEQUENCE},</li>
 *     <li>customMap - contains various key-value pairs that can override an existing standalone attributes.
 *     Null-key attribute is skipped from resulting map.</li>
 * </ul>
 * The construction of resulting map uses non null attributes.
 * <br/><br/>
 * <h3>Example 1:</h3>
 * <pre>
 *     SecurityEventProperties.builder().withMsg("My message").build().toMap();
 *     // Resulting Map
 *     Map<String, Object> details = new LinkedHashMap<>();
 *     details.put("msg", "My message");
 * </pre>
 * <br/>
 * <h3>Example 2:</h3>
 * <pre>
 *     SecurityEventProperties.builder()
 *         .withMsg("My message")
 *         .withOldsequence("old sequence")
 *         .withSequence("key sequence")
 *         .build()
 *     // Resulting Map
 *     Map<String, Object> details = new LinkedHashMap<>();
 *     details.put("msg", "My message");
 *     details.put("oldsequence", "old sequence");
 *     details.put("sequence", "key sequence");
 * <br/>
 * <h3>Example 3:</h3>
 * <pre>
 *     SecurityEventProperties.builder()
 *          .withMsg("My message")
 *          .withCustomMap(myCustomMap)
 *          .build()
 *     // Where:
 *     // myCustomMap = new Map&lt;Object, Object&gt;();
 *     // myCustomMap.put("MyKey1", new Integer("22"));
 *     // myCustomMap.put("MyKey2", new Properties());
 *     // myCustomMap.put("MyKey3", "I have XML escape char &");
 *     // Resulting Map
 *     Map<String, Object> details = new LinkedHashMap<>();
 *     details.put("msg", "My message");
 *     details.put("MyKey1", new Integer("22"));
 *     details.put("MyKey2", new Properties());
 *     details.put("MyKey3", "I have XML escape char &amp;");
 * </pre>
 * @see org.cesecore.audit.log.SecurityEventsLoggerSession#log(AuthenticationToken, EventType, EventStatus, ModuleType, ServiceType, String, String, String, Map)
 * @version $Id$
 */
public class SecurityEventProperties {

    private static final Logger log = Logger.getLogger(SecurityEventProperties.class);
    //
    public static final String CERT_SIGN_KEY = "certSignKey";
    public static final String CRL_SIGN_KEY = "crlSignKey";
    public static final String ERROR = "error";
    public static final String MSG = "msg";
    public static final String OLD_PROPERTIES = "oldproperties";
    public static final String OLD_SEQUENCE = "oldsequence";
    public static final String PROPERTIES = "properties";
    public static final String SEQUENCE = "sequence";
    //
    // Contains the list of 'standalone' attributes to check possible override attempts by customMap
    // An example:
    // msg - might be defined as a field having value "MyMessage"
    // customMap may contain key-value pair msg=MyOtherMessage
    // That would result in output msg=MyOtherMessage with a warning about overlapping attribute
    private final List<String> STANDALONE_ATTRIBUTE_LIST = Arrays.asList(
            CERT_SIGN_KEY,
            CRL_SIGN_KEY,
            ERROR,
            MSG,
            OLD_PROPERTIES,
            OLD_SEQUENCE,
            PROPERTIES,
            SEQUENCE
    );
    // Standalone attributes
    private final String certSignKey;
    private final String crlSignKey;
    private final String error;
    private final String msg;
    private final Properties oldproperties;
    private final String oldsequence;
    private final Properties properties;
    private final String sequence;
    // Custom map to contain additional attributes
    private final Map<?, ?> customMap;

    // Private constructor, use builder
    private SecurityEventProperties(
            final String certSignKey,
            final String crlSignKey,
            final String error,
            final String msg,
            final Properties oldproperties,
            final String oldsequence,
            final Properties properties,
            final String sequence,
            final Map<?, ?> customMap
    ) {
        this.certSignKey = certSignKey;
        this.crlSignKey = crlSignKey;
        this.error = error;
        this.msg = msg;
        this.oldproperties = oldproperties;
        this.oldsequence = oldsequence;
        this.properties = properties;
        this.sequence = sequence;
        this.customMap = customMap;
    }

    /**
     * Returns the builder instance of this class.
     * @return SecurityEventPropertiesBuilder
     */
    public static SecurityEventPropertiesBuilder builder() {
        return new SecurityEventPropertiesBuilder();
    }

    /**
     * Transforms the flat structure of non null attributes into Map&lt;String, Object&gt;.
     * @return The map of non null attributes.
     */
    public Map<String, Object> toMap() {
        final Map<String, Object> map = new LinkedHashMap<>();
        if(certSignKey != null) {
            map.put(CERT_SIGN_KEY, certSignKey);
        }
        if(crlSignKey != null) {
            map.put(CRL_SIGN_KEY, crlSignKey);
        }
        if(error != null) {
            map.put(ERROR, error);
        }
        if(msg != null) {
            map.put(MSG, msg);
        }
        if(oldproperties != null) {
            map.put(OLD_PROPERTIES, oldproperties);
        }
        if(oldsequence != null) {
            map.put(OLD_SEQUENCE, oldsequence);
        }
        if(properties != null) {
            map.put(PROPERTIES, properties);
        }
        if(sequence != null) {
            map.put(SEQUENCE, sequence);
        }
        if (MapUtils.isNotEmpty(customMap)) {
            for (Map.Entry<?, ?> entry : customMap.entrySet()) {
                final Object keyObject = entry.getKey();
                if(keyObject != null) {
                    // Warn about override of a standalone property
                    if(STANDALONE_ATTRIBUTE_LIST.contains(keyObject.toString())) {
                        log.warn("The standalone property [" + keyObject.toString() + "] was overridden by property in custom map.");
                    }
                    map.put(keyObject.toString(), entry.getValue());
                }
                else {
                    log.warn("Got an entry with null key, excluding from the result map.");
                }
            }
        }
        return map;
    }

    /**
     * Builder.
     */
    public static class SecurityEventPropertiesBuilder {

        private String certSignKey;
        private String crlSignKey;
        private String error;
        private String msg;
        private Properties oldproperties;
        private String oldsequence;
        private Properties properties;
        private String sequence;
        private Map<?, ?> customMap;

        private SecurityEventPropertiesBuilder() {
        }

        public SecurityEventPropertiesBuilder withCertSignKey(final String certSignKey) {
            this.certSignKey = certSignKey;
            return this;
        }

        public SecurityEventPropertiesBuilder withCrlSignKey(final String crlSignKey) {
            this.crlSignKey = crlSignKey;
            return this;
        }

        public SecurityEventPropertiesBuilder withError(final String error) {
            this.error = error;
            return this;
        }

        public SecurityEventPropertiesBuilder withMsg(final String msg) {
            this.msg = msg;
            return this;
        }

        public SecurityEventPropertiesBuilder withOldproperties(final Properties oldproperties) {
            this.oldproperties = oldproperties;
            return this;
        }

        public SecurityEventPropertiesBuilder withOldsequence(final String oldsequence) {
            this.oldsequence = oldsequence;
            return this;
        }

        public SecurityEventPropertiesBuilder withProperties(final Properties properties) {
            this.properties = properties;
            return this;
        }

        public SecurityEventPropertiesBuilder withSequence(final String sequence) {
            this.sequence = sequence;
            return this;
        }

        public SecurityEventPropertiesBuilder withCustomMap(final Map<?, ?> customMap) {
            this.customMap = customMap;
            return this;
        }

        public SecurityEventProperties build() {
            return new SecurityEventProperties(certSignKey, crlSignKey, error, msg, oldproperties, oldsequence, properties, sequence, customMap);
        }
    }
}
