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

import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

/**
 * 
 *
 */
public class CK_CP5_AUTH_DATA extends Structure {
    
    public NativeLong ulModulusLen;
    public Pointer pModulus;
    public NativeLong ulPublicExponentLen;
    public Pointer pPublicExponent;
    public byte protocol;

    
    public CK_CP5_AUTH_DATA() {
        super();
        this.setAlignType(ALIGN_DEFAULT);
    }

    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("ulModulusLen", "pModulus", "ulPublicExponentLen", "pPublicExponent", "protocol");
    }
    
    public CK_CP5_AUTH_DATA(Pointer peer) {
        super(peer);
    }
    
    protected ByReference newByReference() { return new ByReference(); }
    protected ByValue newByValue() { return new ByValue(); }
    protected CK_CP5_AUTH_DATA newInstance() { return new CK_CP5_AUTH_DATA(); }
    
    public static class ByReference extends CK_CP5_AUTH_DATA implements Structure.ByReference {};
    public static class ByValue extends CK_CP5_AUTH_DATA implements Structure.ByValue {};
}