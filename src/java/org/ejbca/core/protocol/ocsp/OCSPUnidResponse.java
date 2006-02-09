/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.protocol.ocsp;

import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;

/** Class holding data returned by the OCSPUnidExtension
 * 
 * @author tomas
 * @version $Id: OCSPUnidResponse.java,v 1.5 2006-02-09 11:17:49 anatom Exp $
 *
 */
public class OCSPUnidResponse {
	
    /** Constants capturing the OCSP response status 
     * 
     */
    public static final int OCSP_GOOD = 1;
    public static final int OCSP_REVOKED = 2;
    public static final int OCSP_UNKNOWN = 3;

    /**
     * Constants for error status
     */
    public static final int ERROR_NO_ERROR = 0;
	public static final int ERROR_UNKNOWN = 1;
	public static final int ERROR_UNAUTHORIZED = 2;
	public static final int ERROR_NO_RESPONSE = 3;
	public static final int ERROR_INVALID_SIGNATURE = 4;
    public static final int ERROR_NO_OCSP_URI = 5;

	/*
	 * Private vaiables
	 */
	private OCSPResp resp = null;
	private String fnr = null;
	private int httpReturnCode = 200;
	private int errCode = OCSPUnidResponse.ERROR_NO_ERROR;
	
	public OCSPUnidResponse() {
	}
	public OCSPUnidResponse(OCSPResp ocspresp) {
		this.resp = ocspresp;
	}
	public int getHttpReturnCode() {
		return httpReturnCode;
	}
	public void setHttpReturnCode(int code) {
		httpReturnCode = code;
	}
	public int getErrorCode() {
		return errCode;
	}
	public void setErrorCode(int code) {
		errCode = code;
	}
	public String getFnr() {
		return fnr;
	}
	public void setFnr(String fnr) {
		this.fnr = fnr;
	}
	public OCSPResp getResp() {
		return resp;
	}
	public void setResp(OCSPResp resp) {
		this.resp = resp;
	}
	public int getStatus() {
        if (resp == null) {
            return OCSPUnidResponse.OCSP_UNKNOWN;
        }
		try {
			BasicOCSPResp brep;
			brep = (BasicOCSPResp) resp.getResponseObject();
			SingleResp[] singleResps = brep.getResponses();
			SingleResp singleResp = singleResps[0];
			Object status = singleResp.getCertStatus();
			if (status == null) {
				return OCSPUnidResponse.OCSP_GOOD;
			}
			if (status instanceof RevokedStatus) {
				return OCSPUnidResponse.OCSP_REVOKED;
			}
			if (status instanceof UnknownStatus) {
				return OCSPUnidResponse.OCSP_UNKNOWN;
			}
		} catch (OCSPException e) {
			// Ignore, default return
		}
		return OCSPUnidResponse.OCSP_UNKNOWN;
		
	}
	
	
}
