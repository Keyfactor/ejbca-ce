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

package org.ejbca.core.protocol.ocsp.extension.unid;

import java.util.Date;

import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;

/** Class holding data returned by the OCSPUnidExtension
 * 
 * @version $Id$
 *
 */
public class OCSPUnidResponse {
	
    /** Constants capturing the OCSP response status. 
     * These are the return codes defined in the RFC. 
     * The codes are just used for simple access to the OCSP return value. 
     */
    public static final int OCSP_GOOD = 0;
    public static final int OCSP_REVOKED = 1;
    public static final int OCSP_UNKNOWN = 2;

    //
    // Constants for error status
    //
    /**
     * This is the standard code when no error occurred. Ideally this should always be the returned value.
     */
    public static final int ERROR_NO_ERROR = 0;
    /**
     * An unknown error has occurred (for example internal server error on the OCSP responder) .
     */
	public static final int ERROR_UNKNOWN = 1;
    /**
     * You are not authorized to perform a FNR/UNID lookup.
     */
	public static final int ERROR_UNAUTHORIZED = 2;
    /**
     * There was no response from the server.
     */
	public static final int ERROR_NO_RESPONSE = 3;
    /**
     * This error is returned when the signature of the OCSP-response sent by the server has an invalid 
     * signature. This should typically never happen unless the OCSP-server is compromised in someway, 
     * a fake OCSP-server is installed or something went wrong with the communication so the response 
     * was truncated.
     */
	public static final int ERROR_INVALID_SIGNATURE = 4;
    /**
     * This error is returned when the signerId in the OCSP-response sent by the server does not match
     * the first certificate in the chain in the response. 
     * This should typically never happen unless the OCSP-server is broken. 
     */
	public static final int ERROR_INVALID_SIGNERID = 5;
    /**
     * This error is returned when the OCSP signers certificate can not be verified using the CA-certificate.
     * This should typically never happen unless the OCSP-server is broken or compromised. 
     */
	public static final int ERROR_INVALID_SIGNERCERT = 6;
    /**
     * You did not specify a URI in the call, and there is not one embedded in the certificate.
     */
    public static final int ERROR_NO_OCSP_URI = 7;
    /**
     * The nonce in the response did not match the nonce sent in the request.
     */
    public static final int ERROR_INVALID_NONCE = 8;

	/*
	 * Private variables
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
	
	/** Returns the OCSP response status
	 * 
	 * @return the response code of the OCSP message, OCSPRespBuilder.XX for example OCSPRespBuilder.SIG_REQUIRED
	 */
	public int getResponseStatus() {
        if (resp == null) {
            return OCSPUnidResponse.ERROR_UNKNOWN;
        }
        return resp.getStatus();
	}
	
	public Date getProducedAt() throws OCSPException {
		return ((BasicOCSPResp)resp.getResponseObject()).getProducedAt();
	}
	
	public Date getThisUpdate() throws OCSPException {
		return ((BasicOCSPResp)resp.getResponseObject()).getResponses()[0].getThisUpdate();
	}
	
	public Date getNextUpdate() throws OCSPException {
		return ((BasicOCSPResp)resp.getResponseObject()).getResponses()[0].getNextUpdate();
	}
	
}
