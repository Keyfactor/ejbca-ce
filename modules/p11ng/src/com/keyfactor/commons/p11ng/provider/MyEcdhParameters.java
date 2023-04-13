/*************************************************************************
 *                                                                       *
 *  Keyfactor Commons - Proprietary Modules:                             *
 *                                                                       *
 *  Copyright (c), Keyfactor Inc. All rights reserved.                   *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package com.keyfactor.commons.p11ng.provider;

import java.util.Arrays;
import java.util.List;

import com.sun.jna.Memory;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;

public class MyEcdhParameters extends Structure {
    public long kdf;
    public long shared_data_len;
    public Pointer shared_data;
    public long public_data_len;
    public Pointer public_data;
    
    protected MyEcdhParameters(Memory pubKeyEncoded) {
        kdf = 1;
//        shared_data_len = new NativeLong(0);
        shared_data = Pointer.NULL;
        public_data_len = pubKeyEncoded.size();
        public_data = pubKeyEncoded;
    }
    
    @Override
    protected List<String> getFieldOrder() {
        return Arrays.asList("kdf", "shared_data_len", "shared_data", "public_data_len", "public_data");
    }
}