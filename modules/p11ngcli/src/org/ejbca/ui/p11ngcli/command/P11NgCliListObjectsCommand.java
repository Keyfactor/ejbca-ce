package org.ejbca.ui.p11ngcli.command;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import javax.security.auth.x500.X500Principal;

import org.apache.log4j.Logger;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.ui.p11ngcli.helper.P11NgCliHelper;
import org.pkcs11.jacknji11.CEi;
import org.pkcs11.jacknji11.CKA;
import org.pkcs11.jacknji11.CKO;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.Hex;

public class P11NgCliListObjectsCommand extends P11NgCliCommandBase {

    private static final Logger log = Logger.getLogger(P11NgCliListObjectsCommand.class);

    private static final String LIBFILE = "-libfile";
    private static final String SLOT = "-slot";
    private static final String PIN = "-pin";

    private static CEi ce;

    //Register all parameters
    {
        registerParameter(
                new Parameter(LIBFILE, "lib file", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, "Shared library path"));
        registerParameter(new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Slot on the HSM which will be used."));
        registerParameter(new Parameter(PIN, "PIN for the slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The pin which is used to connect to HSM slot."));
    }

    @Override
    public String getMainCommand() {
        return "listobjects";
    }

    @Override
    public String getCommandDescription() {
        return "List objects availabel on the slot.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final String lib = parameters.get(LIBFILE);
        try {
            ce = P11NgCliHelper.provideCe(lib);
            final long slotId = Long.parseLong(parameters.get(SLOT));
            ce.Initialize();
            long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);

            // tmp - remove later
            //long slot = ce.GetSlot("RootCA");
            ce.Login(session, CKU.USER, parameters.get(PIN).getBytes());
            long[] privateObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PRIVATE_KEY));
            System.out.println("Private Key Objects: " + Arrays.toString(privateObjects));
            StringBuilder buff = new StringBuilder();
            for (long object : privateObjects) {
                printGeneralObjectInfo(buff, object, session);
            }
            System.out.println(buff.toString());

            long[] publicObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.PUBLIC_KEY));
            System.out.println("Public Key Objects: " + Arrays.toString(publicObjects));
            buff = new StringBuilder();
            for (long object : publicObjects) {
                printGeneralObjectInfo(buff, object, session);
            }
            System.out.println(buff.toString());

            long[] certificateObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.CERTIFICATE));
            System.out.println("Certificate Objects: " + Arrays.toString(certificateObjects));
            buff = new StringBuilder();
            for (long object : certificateObjects) {
                printGeneralObjectInfo(buff, object, session);
                printCertificateObjectInfo(buff, object, session);
            }
            System.out.println(buff.toString());

            long[] secretObjects = ce.FindObjects(session, new CKA(CKA.CLASS, CKO.SECRET_KEY));
            System.out.println("Secret Objects: " + Arrays.toString(secretObjects));
            buff = new StringBuilder();
            for (long object : secretObjects) {
                printGeneralObjectInfo(buff, object, session);
            }
            System.out.println(buff.toString());
        } finally {
            ce.Finalize();
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
    
    private static void printGeneralObjectInfo(StringBuilder buff, long object, long session) {
        buff.append("Object ").append(object).append("\n");
        printStringOrHexObjectInfo(buff, object, session, CKA.ID, "CKA_ID");
        printStringOrHexObjectInfo(buff, object, session, CKA.LABEL, "CKA_LABEL");
    }
    
    private static void printCertificateObjectInfo(StringBuilder buff, long object, long session) {
        printX509NameObjectInfo(buff, object, session, CKA.SUBJECT, "CKA_SUBJECT");
        printX509NameObjectInfo(buff, object, session, CKA.ISSUER, "CKA_ISSUER");
    }
    
    private static void printX509NameObjectInfo(StringBuilder buff, long object, long session, long cka, String name) {
        CKA ckaValue = ce.GetAttributeValue(session, object, cka);
        byte[] value = ckaValue.getValue();
        buff.append("   ").append(name).append(":    ");
        if (value == null) {
            buff.append("-");
        } else {
            buff.append(" \"").append(new X500Principal(value).toString()).append("\"");
        }
        buff.append("\n");
    } 
    
    private static void printStringOrHexObjectInfo(StringBuilder buff, long object, long session, long cka, String name) {
        CKA ckaValue = ce.GetAttributeValue(session, object, cka);
        byte[] value = ckaValue.getValue();
        buff.append("   ").append(name).append(":    ");
        if (value == null) {
            buff.append("-");
        } else {
            buff.append("0x").append(Hex.b2s(ckaValue.getValue()));
            buff.append(" \"").append(new String(ckaValue.getValue(), StandardCharsets.UTF_8)).append("\"");
        }
        buff.append("\n");
    }

}
