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

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.ptr.PointerByReference;

/**
 * 
 *
 */
public class PToPBackupObj extends PointerByReference implements Structure.ByReference {

    public PToPBackupObj(Pointer p) {
        super(p);
    } 
    
}