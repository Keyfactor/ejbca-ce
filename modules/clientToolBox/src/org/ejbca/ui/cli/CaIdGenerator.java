package org.ejbca.ui.cli;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.cesecore.util.CertTools;

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
