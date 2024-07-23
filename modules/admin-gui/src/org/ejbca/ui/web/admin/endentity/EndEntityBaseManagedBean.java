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
package org.ejbca.ui.web.admin.endentity;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;

import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.ui.web.admin.BaseManagedBean;
import org.ejbca.ui.web.admin.rainterface.UserView;

public class EndEntityBaseManagedBean extends BaseManagedBean {

    private static final long serialVersionUID = 1L;

    protected UserView userData = null;

    /**
     * Parses certificate extension data from a String of properties in Java 
     * Properties format and store it in the extended information.
     *
     * @param extensionData properties to parse and store.
     */
    @SuppressWarnings({ "rawtypes", "unchecked" })
    public void setExtensionData(final String extensionData) {
        Properties properties = new Properties();
        try {
            properties.load(new StringReader(extensionData));
        } catch (IOException ex) {
            // Should not happen as we are only reading from a String.
            throw new RuntimeException(ex);
        }

        // Remove old extensiondata
        Map data = (Map) this.userData.getExtendedInformation().getData();
        // We have to use an iterator in order to remove an item while iterating, if we try to remove an object from
        // the map while looping over keys we will get a ConcurrentModificationException
        Iterator it = data.keySet().iterator();
        while (it.hasNext()) {
            Object o = it.next();
            if (o instanceof String) {
                String key = (String) o;
                if (key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                    //it.remove() will delete the item from the map
                    it.remove();
                }
            }
        }

        // Add new extensiondata
        for (Object o : properties.keySet()) {
            if (o instanceof String) {
                String key = (String) o;
                data.put(ExtendedInformation.EXTENSIONDATA + key, properties.getProperty(key));
            }
        }

        // Updated ExtendedInformation to use the new data
        this.userData.getExtendedInformation().loadData(data);
    }

    /**
     * @return The extension data read from the extended information and 
     * formatted as in a Properties file.
     */
    public String getExtensionData() {
        final String result;
        if (this.userData.getExtendedInformation() == null) {
            result = "";
        } else {
            @SuppressWarnings("rawtypes")
            Map data = (Map) this.userData.getExtendedInformation().getData();
            Properties properties = new Properties();

            for (Object o : data.keySet()) {
                if (o instanceof String) {
                    String key = (String) o;
                    if (key.startsWith(ExtendedInformation.EXTENSIONDATA)) {
                        String subKey = key.substring(ExtendedInformation.EXTENSIONDATA.length());
                        properties.put(subKey, data.get(key));
                    }
                }

            }

            // Render the properties and remove the first line created by the Properties class.
            StringWriter out = new StringWriter();
            try {
                properties.store(out, null);
            } catch (IOException ex) {
                // Should not happen as we are using a StringWriter
                throw new RuntimeException(ex);
            }

            StringBuffer buff = out.getBuffer();
            String lineSeparator = System.getProperty("line.separator");
            int firstLineSeparator = buff.indexOf(lineSeparator);

            result = firstLineSeparator >= 0 ? buff.substring(firstLineSeparator + lineSeparator.length()) : buff.toString();
        }
        return result;
    }
}
