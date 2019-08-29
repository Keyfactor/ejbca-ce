package org.ejbca.ui.p11ngcli.command;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.spec.RSAPublicKeySpec;

import org.apache.commons.cli.ParseException;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.keys.token.p11ng.CK_CP5_AUTH_DATA;
import org.cesecore.keys.token.p11ng.CK_CP5_INITIALIZE_PARAMS;
import org.cesecore.keys.token.p11ng.provider.CryptokiDevice;
import org.cesecore.keys.token.p11ng.provider.CryptokiManager;
import org.ejbca.configdump.ConfigDumpSetting.ItemType;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.pkcs11.jacknji11.CKM;
import org.pkcs11.jacknji11.CKR;
import org.pkcs11.jacknji11.CKRException;
import org.pkcs11.jacknji11.CKU;
import org.pkcs11.jacknji11.CK_SESSION_INFO;
import org.pkcs11.jacknji11.LongRef;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;

public class P11NgCliKeyAuthorizationInitCommand extends P11NgCliCommandBase {
    
    private static final Logger log = Logger.getLogger(P11NgCliKeyAuthorizationInitCommand.class);
    
    private static final String COMMAND = "keyauthorizationinit";
    private static final String ALIAS = "alias";
    private static final String SLOT = "slot";
    private static final String PIN = "pin";
    private static final String USER_AND_PIN = "user_and_pin";
    private static final String KAK_FILE_PATH = "kak_file_path";
    
    //Register all parameters
    {
        registerParameter(
                new Parameter(ALIAS, "alias", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Alias of the key pair on the HSM."));
        registerParameter(
                new Parameter(SLOT, "HSM slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "Slot on the HSM which will be used."));
        registerParameter(
                new Parameter(PIN, "PIN for the slot", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT, 
                        "The pin which is used to connect to HSM slot."));
        registerParameter(
                new Parameter(USER_AND_PIN, "User name and pin for running the command", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "This option is used to provide user cridential for running the CP5 command."));
        registerParameter(
                new Parameter(KAK_FILE_PATH, "KAK file path", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                        "The path which will be used to save the KAK file to and later for authorization the KAK will be read from it."));
    }

    @Override
    public String getMainCommand() {
        return COMMAND;
    }

    @Override
    public String getCommandDescription() {
        return "Initializes a key on the CP5 HSM, needed to be done before key could be used!";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        final long slotId = Long.parseLong(parameters.get(SLOT));
        CryptokiDevice device = CryptokiManager.getInstance().getDevice(libName, libDir);
        CryptokiDevice.Slot slot = device.getSlot(slotId);

        final String alias = commandLine.getOptionValue(ALIAS);
        final String kakFilePath = commandLine.getOptionValue(KAK_FILE_PATH);
        // Getting the key if it exist on the HSM slot with the provided alias
        

        
        //final long keyFromHSM = getKeyIfExists(commandLine, slot, alias);
        
        // KAK generation part
        KeyPair kakPair = generateKeyPair(); 
        Key kakPublicKey = kakPair.getPublic();
        Key kakPrivateKey = kakPair.getPrivate();

        // Saving the private key, later it will be used in key authorization section.
        try { 
            savePrivateKey(kakFilePath, kakPrivateKey);
        } catch (IOException e) {
            LOG.error("IOException happened while saving the kak private key on the disk!", e);
        }
        
        RSAPublicKeySpec publicSpec = (RSAPublicKeySpec) generateKeySpec(kakPublicKey);
        BigInteger kakPublicExponent  = publicSpec.getPublicExponent();
        BigInteger kakModulus = publicSpec.getModulus();
        
        byte[] kakModBuf = new byte[bitsToBytes(KAK_SIZE)];
        byte[] kakPubExpBuf = new byte[KAK_PUBLIC_EXP_BUF_SIZE];
        
        int kakModLen = kakModulus.toByteArray().length;
        int kakPubExpLen = kakPublicExponent.toByteArray().length;

        assert(kakModBuf.length >= kakModLen);
        assert(kakPubExpBuf.length >= kakPubExpLen);
        
        kakModBuf = kakModulus.toByteArray();
        kakPubExpBuf = kakPublicExponent.toByteArray();

        CK_CP5_INITIALIZE_PARAMS params = new CK_CP5_INITIALIZE_PARAMS();
        CK_CP5_AUTH_DATA authData = new CK_CP5_AUTH_DATA();
        authData.ulModulusLen = new NativeLong(kakModLen);
        
        // allocate sufficient native memory to hold the java array Pointer ptr = new Memory(arr.length);
        // Copy the java array's contents to the native memory ptr.write(0, arr, 0, arr.length);
        Pointer kakModulusPointer = new Memory(kakModLen);
        kakModulusPointer.write(0, kakModBuf, 0, kakModLen);
        authData.pModulus = kakModulusPointer;
        authData.ulPublicExponentLen = new NativeLong(kakPubExpLen);
        
        Pointer kakPublicKeyExponentPointer = new Memory(kakPubExpLen);
        kakPublicKeyExponentPointer.write(0, kakPubExpBuf, 0, kakPubExpLen);
        authData.pPublicExponent = kakPublicKeyExponentPointer;
        authData.protocol = (byte) CKM.CP5_KEY_AUTH_PROT_RSA_PSS_SHA256;

        params.authData = authData;
        params.bAssigned = KEY_AUTHORIZATION_ASSIGNED;
        
        long session = ce.OpenSession(slotId, CK_SESSION_INFO.CKF_RW_SESSION | CK_SESSION_INFO.CKF_SERIAL_SESSION, null, null);
        ce.Login(session, CKU.CKU_CS_GENERIC, commandLine.getOptionValue(USER_AND_PIN).getBytes(StandardCharsets.UTF_8));
        
        params.write(); // Write data before passing structure to function
        CKM mechanism = new CKM(CKM.CKM_CP5_INITIALIZE, params.getPointer(), params.size());
        
        byte[] hash = new byte[HASH_SIZE];
        long hashLen = hash.length;

        // Get the private key from HSM
        long[] privateKeyObjects = getPrivateKeyFromHSM(slot, alias);
        
        long rvAuthorizeKeyInit = ce.authorizeKeyInit(session, mechanism, privateKeyObjects[0], hash, new LongRef(hashLen));
        if (rvAuthorizeKeyInit != CKR.OK) {
            cleanUp(session);
            throw new CKRException(rvAuthorizeKeyInit);
        }

        byte[] initSig = new byte[bitsToBytes(KAK_SIZE)];
        try {
            initSig = signHashPss(hash, hashLen, initSig.length, kakPrivateKey);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException 
                 | InvalidAlgorithmParameterException | SignatureException e) {
            log.error("Error happened while signing the hash!", e);
        }

        long rvAuthorizeKey = ce.authorizeKey(session, initSig, initSig.length);
        if (rvAuthorizeKey != CKR.OK) {
            cleanUp(session);
            throw new CKRException(rvAuthorizeKey);
        }

        cleanUp(session);
        break;
    }

    @Override
    public String getFullHelpText() {
        return "";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
