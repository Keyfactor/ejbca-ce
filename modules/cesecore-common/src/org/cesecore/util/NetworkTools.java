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
package org.cesecore.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;

import org.apache.log4j.Logger;

/**
 * Helper methods for basic network interactions.
 * 
 * @version $Id$
 */
public abstract class NetworkTools {
    private static final Logger log = Logger.getLogger(NetworkTools.class);

    /** @return the URL object of the provided CDP if it is well formed and uses the HTTP protocol. null otherwise */
    public static URL getValidHttpUrl(final String cdp) {
        if (cdp==null) {
            return null;
        }
        final URL url;
        try {
            url = new URL(cdp);
        } catch (MalformedURLException e) {
            return null;
        }
        if (!"http".equals(url.getProtocol().toLowerCase())) {
            return null;
        }
        return url;
    }

    /** @return the data found at the provided URL if available and the size is less the maxSize */
    public static byte[] downloadDataFromUrl(final URL url, final int maxSize) {
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final byte data[] = new byte[32768];    // 32KiB at the time
        int downloadedBytes = 0;
        InputStream is = null;
        try {
            is = url.openStream();
            int count;
            while ((count = is.read(data)) != -1) {
                baos.write(data, 0, count);
            }
            downloadedBytes += count;
            if (downloadedBytes>maxSize) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to download data from " + url.toString() + ". Size exceedes " + maxSize + " bytes.");
                }
                return null;
            }
        } catch (IOException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to download data from " + url.toString(), e);
            }
            return null;
        } finally {
            if (is!=null) {
                try {
                    is.close();
                } catch (IOException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to download data from " + url.toString(), e);
                    }
                }
            }
        }
        return baos.toByteArray();
    }
}
