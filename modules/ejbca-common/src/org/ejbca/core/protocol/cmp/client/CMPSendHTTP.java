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

package org.ejbca.core.protocol.cmp.client;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.ui.web.LimitLengthASN1Reader;

/**
 * Client to send message to CMP server over HTTP.
 * 
 * @version $Id$
 */
public class CMPSendHTTP {
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

	public final String contentType;
	public final byte response[];
	public final int responseCode;

	private CMPSendHTTP(String ct, byte ba[], int rc) {
		this.contentType = ct;
		this.response = ba;
		this.responseCode = rc;
	}

	public static CMPSendHTTP sendMessage(final byte[] message, final String hostName,
	        final int port, final String urlPath, final boolean doClose) throws MalformedURLException, IOException {
	    return sendMessage(message, "http://"+hostName+":"+port+urlPath, doClose);
	}

	public static CMPSendHTTP sendMessage(final byte[] message, final String url, final boolean doClose) throws MalformedURLException, IOException {
		boolean isError = true;
		final HttpURLConnection con = (HttpURLConnection)new URL(url).openConnection();
		try {
			// POST the CMP request
			con.setDoOutput(true);
			con.setRequestMethod("POST");
			con.setRequestProperty("Content-type", "application/pkixcmp");
			con.connect();
			final OutputStream os = con.getOutputStream();
			os.write(message);
			os.close();
			final String contentType = con.getContentType();
			final int responseCode = con.getResponseCode();
			if (responseCode!=HttpURLConnection.HTTP_OK) {
				return new CMPSendHTTP(contentType, null, responseCode);
			}
            final LimitLengthASN1Reader limitLengthASN1Reader = new LimitLengthASN1Reader(con.getInputStream(), con.getContentLength());
            try {
                final byte response[] = limitLengthASN1Reader.readFirstASN1Object();
                isError = false;
                return new CMPSendHTTP(contentType, response, responseCode);
            } catch (MalformedRequestException e) {
                throw new IOException(intres.getLocalizedMessage("cmp.errornoasn1"), e);
            } finally {
                limitLengthASN1Reader.close();
            }
		} finally {
			if (doClose || isError) {
				con.disconnect();
			}
		}
	}
}
