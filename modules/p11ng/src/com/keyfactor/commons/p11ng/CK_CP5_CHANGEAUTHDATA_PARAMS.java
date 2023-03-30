/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.commons.p11ng;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * 
 * 
 *
 */
public class CK_CP5_CHANGEAUTHDATA_PARAMS extends Structure {
    
    public CK_CP5_AUTH_DATA authData;

    public CK_CP5_CHANGEAUTHDATA_PARAMS() {
        super();
        this.setAlignType(ALIGN_DEFAULT);
    }
    
    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("authData");
    }
    
    public CK_CP5_CHANGEAUTHDATA_PARAMS(Pointer peer) {
        super(peer);
    }
    
    protected ByReference newByReference() { return new ByReference(); }
    protected ByValue newByValue() { return new ByValue(); }
    protected CK_CP5_CHANGEAUTHDATA_PARAMS newInstance() { return new CK_CP5_CHANGEAUTHDATA_PARAMS(); }

    public static class ByReference extends CK_CP5_CHANGEAUTHDATA_PARAMS implements Structure.ByReference {};
    public static class ByValue extends CK_CP5_CHANGEAUTHDATA_PARAMS implements Structure.ByValue {};

}
