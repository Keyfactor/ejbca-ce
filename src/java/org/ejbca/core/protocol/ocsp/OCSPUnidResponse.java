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
 * @version $Id: OCSPUnidResponse.java,v 1.1 2006-02-05 15:51:02 anatom Exp $
 *
 */
public class OCSPUnidResponse {

	/** Constants capturing the OCSP response status 
	 * 
	 */
	public static final int OCSP_GOOD = 1;
	public static final int OCSP_REVOKED = 2;
	public static final int OCSP_UNKNOWN = 3;
	
	/** Constants capturing the possible error returned
	 * 
	 */
	public static final int ERROR_NO_ERROR = 0;
	public static final int ERROR_UNKNOWN = 1;
	public static final int ERROR_UNAUTHORIZED = 2;
	public static final int ERROR_NO_FNR_MAPPING = 3;
	public static final int ERROR_NO_SERIAL_IN_DN = 4;
	public static final int ERROR_SERVICE_UNAVAILABLE = 5;

	/*
	 * Private vaiables
	 */
	private OCSPResp resp = null;
	private String fnr = null;
	private int errcode = ERROR_NO_ERROR;

	public int getErrcode() {
		return errcode;
	}
	public void setErrcode(int errcode) {
		this.errcode = errcode;
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
		try {
			BasicOCSPResp brep;
			brep = (BasicOCSPResp) resp.getResponseObject();
			SingleResp[] singleResps = brep.getResponses();
			SingleResp singleResp = singleResps[0];
			Object status = singleResp.getCertStatus();
			if (status == null) {
				return OCSP_GOOD;
			}
			if (status instanceof RevokedStatus) {
				return OCSP_REVOKED;
			}
			if (status instanceof UnknownStatus) {
				return OCSP_UNKNOWN;
			}
		} catch (OCSPException e) {
			// Ignore, default return
		}
		return OCSP_UNKNOWN;
		
	}
	
	
}
