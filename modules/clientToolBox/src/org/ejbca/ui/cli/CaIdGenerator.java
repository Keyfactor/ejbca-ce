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

package org.ejbca.ui.cli;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.keyfactor.util.CertTools;

/**
 * <p><b>CaId Module Module</b>
 * <p>Generates CA IDs which can be used with EJBCA.
 *
 * @version $Id$
 */
public class CaIdGenerator extends ClientToolBox {

    @Override
    protected void execute(String[] args) {
        final List<String> argsList = new ArrayList<String>(Arrays.asList(args));
        argsList.remove(getName());
        if (argsList.isEmpty() || argsList.contains("help")) {
            System.out.println("Usage: CaIdGenerator <SubjectDN>");
            return;
        }
        if (argsList.size() > 1) {
            System.out.println("Too many arguments. Type 'help' for more information.");
            return;
        }
        final int id = CertTools.stringToBCDNString(argsList.get(0)).hashCode();
        System.out.println(id);
    }

    @Override
    protected String getName() {
        return "CaIdGenerator";
    }
}
