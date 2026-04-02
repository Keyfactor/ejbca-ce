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

package org.ejbca.core.ejb.ca.publisher;

import org.apache.log4j.Logger;
import org.cesecore.util.Base64GetHashMap;
import org.cesecore.util.Base64PutHashMap;
import org.cesecore.util.SecureXMLDecoder;
import org.ejbca.core.model.ca.publisher.ActiveDirectoryPublisher;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.CustomPublisherContainer;
import org.ejbca.core.model.ca.publisher.LdapPublisher;
import org.ejbca.core.model.ca.publisher.LdapSearchPublisher;
import org.ejbca.core.model.ca.publisher.MultiGroupPublisher;
import org.ejbca.core.model.ca.publisher.PublisherConst;
import org.ejbca.dto.PublisherDataBean;
import org.cesecore.dto.PublisherData;

import java.beans.XMLEncoder;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

public class PublisherDataUtil {

    private static final Logger log = Logger.getLogger(PublisherDataUtil.class);

    static BasePublisher constructPublisher(final int publisherType) {
        switch (publisherType) {
            case PublisherConst.TYPE_LDAPPUBLISHER:
                return new LdapPublisher();
            case PublisherConst.TYPE_LDAPSEARCHPUBLISHER:
                return new LdapSearchPublisher();
            case PublisherConst.TYPE_ADPUBLISHER:
                return new ActiveDirectoryPublisher();
            case PublisherConst.TYPE_MULTIGROUPPUBLISHER:
                return new MultiGroupPublisher();
            case PublisherConst.TYPE_CUSTOMPUBLISHERCONTAINER:
                return new CustomPublisherContainer();
            default:
                throw new IllegalStateException("Invalid or unimplemented publisher type " + publisherType);
        }
    }

    private static HashMap<?, ?> parseDataMapFromPublisher(final PublisherData dto) {
        final var bean = new PublisherDataBean();
        bean.init(dto);
        final var bytes = bean
                .getData()
                .getBytes(StandardCharsets.UTF_8);
        try (SecureXMLDecoder decoder = new SecureXMLDecoder(new ByteArrayInputStream(bytes))) {
            return (HashMap<?, ?>) decoder.readObject();
        } catch (IOException e) {
            final String msg = "Failed to parse PublisherData data map in database: " + e.getMessage();
            if (log.isDebugEnabled()) {
                log.debug(msg + ". Data:\n" + dto.data());
            }
            throw new IllegalStateException(msg, e);
        }
    }

    public static BasePublisher getPublisher(final PublisherData dto) {
        HashMap<?, ?> h = parseDataMapFromPublisher(dto);
        // Handle Base64 encoded string values
        HashMap<?, ?> data = new Base64GetHashMap(h);
        final var publisher = constructPublisher((Integer) (data.get(BasePublisher.TYPE)));
        if (publisher != null) {
            publisher.setPublisherId(dto.id());
            publisher.setName(dto.name());
            publisher.loadData(data);
        }
        return publisher;
    }

    @SuppressWarnings("unchecked")
    public static String toString(final BasePublisher publisher) {
        // We must base64 encode string for UTF safety
        HashMap<Object, Object> a = new Base64PutHashMap();
        a.putAll((HashMap<Object, Object>) publisher.saveData());
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (XMLEncoder encoder = new XMLEncoder(baos)) {
            encoder.writeObject(a);
        }
        try {
            if (log.isDebugEnabled()) {
                log.debug("Publisher data: \n" + baos.toString("UTF8"));
            }
            return baos.toString("UTF8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublisherData setPublisher(final PublisherData dto, BasePublisher publisher) {
        final var bean = new PublisherDataBean();
        bean.init(dto);
        bean.setData(toString(publisher));
        bean.setUpdateCounter(dto.updateCounter()+1);
        return bean.toDto();
    }

    public static void setPublisher(final PublisherDataBean bean, BasePublisher publisher) {
        bean.setData(toString(publisher));
        bean.setUpdateCounter(bean.getUpdateCounter()+1);
    }

}
