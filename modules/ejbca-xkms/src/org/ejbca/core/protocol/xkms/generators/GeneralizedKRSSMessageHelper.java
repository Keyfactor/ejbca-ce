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

package org.ejbca.core.protocol.xkms.generators;

import org.w3._2002._03.xkms_.AuthenticationType;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.PrivateKeyType;
import org.w3._2002._03.xkms_.ProofOfPossessionType;
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.ResultType;
import org.w3._2002._03.xkms_.RevokeRequestType;

/**
 * A Help class used to generalize the different KRSS calls
 * 
 * Needed since there isn't any good inheritense between
 * the request
 * 
 * 
 * @author Philip Vendil 2007 jan 1
 *
 * @version $Id$
 */

public class GeneralizedKRSSMessageHelper {
	
	public static AuthenticationType getAuthenticationType(RequestAbstractType request){
		if(request instanceof RegisterRequestType){
			return ((RegisterRequestType)request).getAuthentication();
		}
		if(request instanceof ReissueRequestType){
			return ((ReissueRequestType)request).getAuthentication();
		}
		if(request instanceof RecoverRequestType){
			return ((RecoverRequestType)request).getAuthentication();
		}
			
		return null;
	}
	
	
	public static ProofOfPossessionType getProofOfPossessionType(RequestAbstractType request){
		if(request instanceof RegisterRequestType){
			return ((RegisterRequestType)request).getProofOfPossession();
		}
		if(request instanceof ReissueRequestType){
			return ((ReissueRequestType)request).getProofOfPossession();
		}
			
		return null;
	}
	
	public static KeyBindingAbstractType getKeyBindingAbstractType(RequestAbstractType request){
		if(request instanceof RegisterRequestType){
			return ((RegisterRequestType)request).getPrototypeKeyBinding();
		}
		if(request instanceof ReissueRequestType){
			return ((ReissueRequestType)request).getReissueKeyBinding();
		}
		if(request instanceof RecoverRequestType){
			return ((RecoverRequestType)request).getRecoverKeyBinding();
		}
		if(request instanceof RevokeRequestType){
			return ((RevokeRequestType)request).getRevokeKeyBinding();
		}
			
		return null;
	}
	
	public static void setPrivateKey(ResultType response, PrivateKeyType privateKeyType){
		if(response instanceof RegisterResultType){
			((RegisterResultType)response).setPrivateKey(privateKeyType);
		}
		if(response instanceof RecoverResultType){
			((RecoverResultType)response).setPrivateKey(privateKeyType);
		}
	}
	


}
