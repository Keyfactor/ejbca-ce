/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.cesecore.certificates.certificateprofile;

import static org.junit.Assume.assumeTrue;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;

import org.apache.commons.codec.binary.Base64;
import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Regression tests for ECA-7277. See {@link org.cesecore.legacy.Eca7277CertificateProfileData} for an explanation why this
 * test is needed.
 *
 * The test contains a canned certificate profile and signature from EJBCA 6.11 and EJBCA 6.14. The canned certificate
 * profile was extracted from EJBCA by applying the following code to e.g. CertificateProfileData.verifyData:
 * <pre>
 * ByteArrayOutputStream bos = new ByteArrayOutputStream();
 * ObjectOutputStream oos;
 * oos = new ObjectOutputStream(bos);
 * oos.writeObject(this.getCertificateProfile());
 *
 * log.error("foo! " + this.getCertificateProfileName() + ": " + Base64.encodeBase64String(bos.toByteArray()));
 * </pre>
 *
 * EJBCA will run verifyData on startup and print the base64 data, it's up for grabs in server.log
 * <pre>
 * cat /opt/wildfly/standalone/log/server.log | grep -C 10 "foo!"
 * </pre>
 * The signature is available directly in the database and can be printed to the screen using the following query (mysql)
 * <pre>
 * USE ejbca;
 * SELECT certificateProfileName,id,rowProtection FROM CertificateProfileData;
 * </pre>
 *
 * This code can be removed once we are sure that all installations have performed post-upgrade on EJBCA version 7.x or later.
 *
 * @version $Id$
 */
@Deprecated
public class Eca7277RegressionTest {
    
    private static final Logger log = Logger.getLogger(Eca7277RegressionTest.class);

    private boolean isDatabaseProtectionImplementationAvailable() {
        try {
            Class.forName("org.cesecore.dbprotection.ProtectedDataIntegrityImpl");
            return true;
        } catch (final ClassNotFoundException e) {
            return false;
        }
    }

    @BeforeClass
    public static void installDatabaseProtectionConfiguration() {
        ConfigurationHolder.instance().clear();
        ConfigurationHolder.updateConfiguration("databaseprotection.enablesign", "true");
        ConfigurationHolder.updateConfiguration("databaseprotection.enableverify", "true");
        ConfigurationHolder.updateConfiguration("databaseprotection.erroronverifyfail", "true");
        ConfigurationHolder.updateConfiguration("databaseprotection.keyid", "123");
        ConfigurationHolder.updateConfiguration("databaseprotection.keyid.0", "123");
        ConfigurationHolder.updateConfiguration("databaseprotection.keylabel.0", "dbStoreKey");
        ConfigurationHolder.updateConfiguration("databaseprotection.classname.0", "org.cesecore.keys.token.SoftCryptoToken");
        ConfigurationHolder.updateConfiguration("databaseprotection.properties.0", null);
        ConfigurationHolder.updateConfiguration("databaseprotection.data.0", "MIACAQMwgAYJKoZIhvcNAQcBoIAkgASCA+"
                + "gwgDCABgkqhkiG9w0BBwGggCSABIIDFzCCAxMwggMPBgsqhkiG9w0BDAoBAqCCArIwggKuMCgGCiqGSIb3DQEMAQMwGgQ"
                + "UoJf9vyr8B9t39behotCowOansBwCAgQABIICgGXl+JjLI1FdinxhnmYyeIArmYRwxCEJY7BP1778vXHhEk34ZIgrZDKo"
                + "TETkjmz3QOZ1jE/lcZL9884zjovz/PdOR7vYP85X803u/vqSMDe+Z7JmCucJ8tGmWxGa6t++X+xFv25U5w5IePQ7FbFnz"
                + "jC4P+Il+E7jDsv8Qap+YW0tiyAWsfkOdSqscSJWMcDH894P8sCO3LBTnpT14AOdLj69YdFOCmrMEFZYbko6zSXFGyeADH"
                + "nJaz3WWU9yHRY90Hz0JBlMuV3eSErCjOf647vRBoshwHMuVGlWya3ZbuACqDE9tq3H9sUQX4G5YubBJdpqyietA/VcXSs"
                + "KPk8OyWXXr2A/U733TAQ08Z+FFir4ogLsIN5mTfCnk8/R+wScqTpT4Ngtd6VjIOcHImRR6tA2yTcJtBhQxBeFbZh108VH"
                + "Cqgx6twLoRHybr/KtGeI+mbK5NgMd0Zi6Q3HNwcvgrnvm7/J+0+PVdWQ6cq2pPYuRW3KIIXQIfu1L5Ax2nZ/prWmy09X9"
                + "P2yvxrl/knynf+Cc2MUhbEu++uSpjBzG3TG7zKFXzTV0J7tsirb7lMQYMiU+8+DW65FK7DRl/MWjSOmYT7ax6yXatFPrc"
                + "5xl6iBhNu9gEY2r9/PotOo8CoUhR4BVDrGmYEBBdGKACZjxGZ71M8h7CziUREdq9seG12Z8yOTOrpXcgQ4hfDNCJpyvpp"
                + "8qu8dsOeeQbNaiZ39TGNDVsRAT44ibvyzmw0BYYQGqS73uOH8IiFOLTip3CSm78Qn4rfVq0pjq/1fKXFrjowl4DWhVpbD"
                + "SptSQtda31lPa5+6/rMM05f+mIV/WT3ouj5uCg2RyeyE3DqPSPn7oowxSjAjBgkqhkiG9w0BCRQxFh4UAGQAYgBTAHQAb"
                + "wByAGUASwBlAHkwIwYJKoZIhvcNAQkVMRYEFMG7BSYBT2CyAkjFNA9qAW8ySV3eAAAAAAAAMIAGCSqGSIb3DQEHBqCAMI"
                + "ACAQAwgAYJKoZIhvcNAQcBMCgGCiqGSIb3DQEMAQYwGgQUCESSXTsDUqs0+/z9Uh1190RzHQYCAgQAoIAEggJg0qFQBFT"
                + "yIlgq3tl6k+xbei3WLiEeX75hTS2Sp1H0eFf1tduo9MwUFGSJwNBEPRHxIFwMLnxbSMZpppDjCEZddxXArORQTJgpCrBF"
                + "TruAum849qQkE5iAXHwv/qaCq2QpE9+mBIICCZLDc+48Orv5j+BlG0aVg+6gluX7mduzJ6A3LbaSsDXs/kMst7R8X4E8n"
                + "gqmYeMFv4kx3Cvs2ytfEAfM3m3PHSF/srw/cm5Kq2STlSbxLrbQEzaWThDHqvHrJZVtiQstcid/CZ0tHgLrv8FAGIMY50"
                + "ZsMumyFZKyLDKO5/qrhCUyVxE4sGS0Snx1dMmv/AN/vP/NjAGbTpdaAqhUry/g0Lr4qkxeqC0NjoRXBrI0rgBvjMdbhB9"
                + "Wt4/tqANJ9w6Q1pgET2UThcLPQlm7QnbUwNDvUmSR6uvFk9gZ75L3Q5xx3iTmLQRPPdAktoR8jM0PM3NEeU56qRj58dh5"
                + "B4qBuJVhZYfzv0YIzVUaMh+ObDRpw4JrccsvZLdYuV8E18ViFZsJDLkeHYOi2at1Vl72mgq/8sEN/9EEvuZTDywO0K0cq"
                + "+hr20VN6DLsdmCp4Y3pwPIgqU16QRSUGp4iXNa32srbon9HahcBnJ2nKxNqc/QqQZ8vd+aiVwIB9VeDS+ESA1hHwzrOBR"
                + "6ETjKQzsQNICodsftTUSAw65KierfI3m4rZJ4ot10log2fTqNNpTr1xbnfYIxudRarDPj0g96dllk1GgLCxobOWodAm8w"
                + "jq6owURwuvFBSzK5oQbcHkahsn1/3QTIdosph0Ogwzk2ztsdalx+C1CQPjgg9sQpDAAAAAAAAAAAAAAAAAAAAAAAAMD0w"
                + "ITAJBgUrDgMCGgUABBTho0WL80msVWn2+P1QzXJk+UXGIgQUDCn5DHvC9Ioqp/a6vgNj1eZT7ScCAgQAAAA=");
        ConfigurationHolder.updateConfiguration("databaseprotection.tokenpin.0", "userpin1");
        ConfigurationHolder.updateConfiguration("databaseprotection.version.0", "2");
        ConfigurationHolder.updateConfiguration("databaseprotection.sigalg.0", "SHA256WithRSA");
    }

    /**
     * Test that a certificate profile created and signed in EJBCA 6.14 verifies. A certificate profile created
     * in EJBCA 6.12-6.14 would not verify on the first attempt since the signature was computed over some data
     * which was refactored by mistake in EJBCA 6.12. The aim of this test is to check that we can recover, "patch"
     * the protect string and verify again without crashing.
     */
    @Test
    public void certificateProfileCreatedInEjbca614Verifies() throws Exception {
        log.trace(">certificateProfileCreatedInEjbca614Verifies");
        assumeTrue(isDatabaseProtectionImplementationAvailable());

        final ByteArrayInputStream bis = new ByteArrayInputStream(
                Base64.decodeBase64("rO0ABXNyAD9vcmcuY2VzZWNvcmUuY2VydGlmaWNhdGVzLmNlcnRpZmljYXRlcHJvZmlsZS5DZXJ0aWZpY2F0ZVByb2Zpb"
                    + "GWQAv2yYUWtSgIAAHhyACxvcmcuY2VzZWNvcmUuaW50ZXJuYWwuVXBncmFkZWFibGVEYXRhSGFzaE1hcOd8vFMpTFJHAg"
                    + "ACWgAIdXBncmFkZWRMAARkYXRhdAAZTGphdmEvdXRpbC9MaW5rZWRIYXNoTWFwO3hwAHNyACJvcmcuY2VzZWNvcmUudXR"
                    + "pbC5CYXNlNjRHZXRIYXNoTWFwBxVvc8BHrukCAAB4cgAXamF2YS51dGlsLkxpbmtlZEhhc2hNYXA0wE5cEGzA+wIAAVoA"
                    + "C2FjY2Vzc09yZGVyeHIAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xke"
                    + "HA/QAAAAAAAwHcIAAABAAAAAG50AAd2ZXJzaW9uc3IAD2phdmEubGFuZy5GbG9hdNrtyaLbPPDsAgABRgAFdmFsdWV4cg"
                    + "AQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHBCOAAAdAAEdHlwZXNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc"
                    + "4AgABSQAFdmFsdWV4cQB+AAoAAAABdAALY2VydHZlcnNpb250AAZYNTA5djN0AA9lbmNvZGVkdmFsaWRpdHl0AAM2bW90"
                    + "ABx1c2VjZXJ0aWZpY2F0ZXZhbGlkaXR5b2Zmc2V0c3IAEWphdmEubGFuZy5Cb29sZWFuzSBygNWc+u4CAAFaAAV2YWx1Z"
                    + "XhwAHQAGWNlcnRpZmljYXRldmFsaWRpdHlvZmZzZXR0AAQtMTBtdAAjdXNlZXhwaXJhdGlvbnJlc3RyaWN0aW9uZm9yd2"
                    + "Vla2RheXNxAH4AFXQAJmV4cGlyYXRpb25yZXN0cmljdGlvbmZvcndlZWtkYXlzYmVmb3Jlc3EAfgAUAXQAHWV4cGlyYXR"
                    + "pb25yZXN0cmljdGlvbndlZWtkYXlzc3IAE2phdmEudXRpbC5BcnJheUxpc3R4gdIdmcdhnQMAAUkABHNpemV4cAAAAAd3"
                    + "BAAAAAdxAH4AGnEAfgAac3EAfgAUAHEAfgAecQB+AB5xAH4AGnEAfgAaeHQAFWFsbG93dmFsaWRpdHlvdmVycmlkZXNxA"
                    + "H4AFAF0ABZhbGxvd2V4dGVuc2lvbm92ZXJyaWRlcQB+ACB0AA9hbGxvd2Rub3ZlcnJpZGVxAH4AFXQAFGFsbG93ZG5vdm"
                    + "VycmlkZWJ5ZWVpcQB+ABV0ABhhbGxvd2JhY2tkYXRlZHJldm9rYXRpb25xAH4AFXQAFXVzZWNlcnRpZmljYXRlc3RvcmF"
                    + "nZXEAfgAgdAAUc3RvcmVjZXJ0aWZpY2F0ZWRhdGFxAH4AIHQAE3N0b3Jlc3ViamVjdGFsdG5hbWVxAH4AIHQAEnVzZWJh"
                    + "c2ljY29uc3RyYW50c3EAfgAgdAAYYmFzaWNjb25zdHJhaW50c2NyaXRpY2FscQB+ACB0ABd1c2VzdWJqZWN0a2V5aWRlb"
                    + "nRpZmllcnEAfgAgdAAcc3ViamVjdGtleWlkZW50aWZpZXJjcml0aWNhbHEAfgAedAAZdXNlYXV0aG9yaXR5a2V5aWRlbn"
                    + "RpZmllcnEAfgAgdAAeYXV0aG9yaXR5a2V5aWRlbnRpZmllcmNyaXRpY2FscQB+AB50ABl1c2VzdWJqZWN0YWx0ZXJuYXR"
                    + "pdmVuYW1lcQB+ACB0AB5zdWJqZWN0YWx0ZXJuYXRpdmVuYW1lY3JpdGljYWxxAH4AFXQAGHVzZWlzc3VlcmFsdGVybmF0"
                    + "aXZlbmFtZXEAfgAgdAAdaXNzdWVyYWx0ZXJuYXRpdmVuYW1lY3JpdGljYWxxAH4AFXQAF3VzZWNybGRpc3RyaWJ1dGlvb"
                    + "nBvaW50cQB+ABV0AB51c2VkZWZhdWx0Y3JsZGlzdHJpYnV0aW9ucG9pbnRxAH4AHnQAHGNybGRpc3RyaWJ1dGlvbnBvaW"
                    + "50Y3JpdGljYWxxAH4AHnQAF2NybGRpc3RyaWJ1dGlvbnBvaW50dXJpdAAAdAAOdXNlZnJlc2hlc3RjcmxxAH4AFXQAF3V"
                    + "zZWNhZGVmaW5lZGZyZXNoZXN0Y3JscQB+AB50AA5mcmVzaGVzdGNybHVyaXEAfgA2dAAJY3JsaXNzdWVycQB+ADZ0ABZ1"
                    + "c2VjZXJ0aWZpY2F0ZXBvbGljaWVzcQB+ACB0ABtjZXJ0aWZpY2F0ZXBvbGljaWVzY3JpdGljYWxxAH4AFXQAE2NlcnRpZ"
                    + "mljYXRlcG9saWNpZXNzcQB+ABwAAAAAdwQAAAAAeHQAFmF2YWlsYWJsZWtleWFsZ29yaXRobXNzcQB+ABwAAAACdwQAAA"
                    + "ACdAAFRUNEU0F0AANSU0F4dAARYXZhaWxhYmxlZWNjdXJ2ZXNzcQB+ABwAAAABdwQAAAABdAAKcHJpbWUyNTZ2MXh0ABN"
                    + "hdmFpbGFibGViaXRsZW5ndGhzc3EAfgAcAAAAA3cEAAAAA3NxAH4ADQAACABzcQB+AA0AAAwAc3EAfgANAAAQAHh0ABlt"
                    + "aW5pbXVtYXZhaWxhYmxlYml0bGVuZ3Roc3EAfgANAAAIAHQAGW1heGltdW1hdmFpbGFibGViaXRsZW5ndGhzcQB+AA0AA"
                    + "BAAdAASc2lnbmF0dXJlYWxnb3JpdGhtcHQAC3VzZWtleXVzYWdlcQB+ACB0AAhrZXl1c2FnZXNxAH4AHAAAAAl3BAAAAA"
                    + "lxAH4AIHEAfgAgcQB+ACBxAH4AFXEAfgAVcQB+ABVxAH4AFXEAfgAVcQB+ABV4dAAVYWxsb3drZXl1c2FnZW92ZXJyaWR"
                    + "lcQB+ABV0ABBrZXl1c2FnZWNyaXRpY2FscQB+ACB0ABN1c2VleHRlbmRlZGtleXVzYWdlcQB+ACB0ABBleHRlbmRlZGtl"
                    + "eXVzYWdlc3EAfgAcAAAAAXcEAAAAAXQAETEuMy42LjEuNS41LjcuMy4xeHQAGGV4dGVuZGVka2V5dXNhZ2Vjcml0aWNhb"
                    + "HEAfgAVdAATdXNlZG9jdW1lbnR0eXBlbGlzdHEAfgAVdAAYZG9jdW1lbnR0eXBlbGlzdGNyaXRpY2FscQB+AB50ABBkb2"
                    + "N1bWVudHR5cGVsaXN0c3EAfgAcAAAAAHcEAAAAAHh0AAxhdmFpbGFibGVjYXNzcQB+ABwAAAACdwQAAAACc3EAfgANznN"
                    + "nfXNxAH4ADU0lspF4dAAOdXNlZHB1Ymxpc2hlcnNzcQB+ABwAAAAAdwQAAAAAeHQADnVzZW9jc3Bub2NoZWNrcQB+ABV0"
                    + "AA51c2VsZGFwZG5vcmRlcnEAfgAgdAAQdXNlY3VzdG9tZG5vcmRlcnEAfgAVdAAUdXNlbWljcm9zb2Z0dGVtcGxhdGVxA"
                    + "H4AFXQAEW1pY3Jvc29mdHRlbXBsYXRldAAAdAANdXNlY2FyZG51bWJlcnEAfgAVdAAMdXNlY25wb3N0Zml4cQB+ABV0AA"
                    + "ljbnBvc3RmaXhxAH4AaXQAEnVzZXN1YmplY3RkbnN1YnNldHEAfgAVdAAPc3ViamVjdGRuc3Vic2V0c3EAfgAcAAAAAHc"
                    + "EAAAAAHh0ABd1c2VzdWJqZWN0YWx0bmFtZXN1YnNldHEAfgAVdAAUc3ViamVjdGFsdG5hbWVzdWJzZXRzcQB+ABwAAAAA"
                    + "dwQAAAAAeHQAF3VzZXBhdGhsZW5ndGhjb25zdHJhaW50cQB+AB50ABRwYXRobGVuZ3RoY29uc3RyYWludHNxAH4ADQAAA"
                    + "AB0AA51c2VxY3N0YXRlbWVudHEAfgAVdAARdXNlcGtpeHFjc3ludGF4djJxAH4AHnQAFnVzZXFjc3RhdGVtZW50Y3JpdG"
                    + "ljYWxxAH4AHnQAFHVzZXFjc3RhdGVtZW50cmFuYW1lcQB+AGl0AA91c2VxY3NlbWF0aWNzaWRxAH4AaXQAFXVzZXFjZXR"
                    + "zaXFjY29tcGxpYW5jZXEAfgAedAAYdXNlcWNldHNpc2lnbmF0dXJlZGV2aWNlcQB+AB50ABN1c2VxY2V0c2l2YWx1ZWxp"
                    + "bWl0cQB+AB50ABBxY2V0c2l2YWx1ZWxpbWl0cQB+AHV0ABNxY2V0c2l2YWx1ZWxpbWl0ZXhwcQB+AHV0ABhxY2V0c2l2Y"
                    + "Wx1ZWxpbWl0Y3VycmVuY3lxAH4AaXQAGHVzZXFjZXRzaXJldGVudGlvbnBlcmlvZHEAfgAedAAVcWNldHNpcmV0ZW50aW"
                    + "9ucGVyaW9kcQB+AHV0ABF1c2VxY2N1c3RvbXN0cmluZ3EAfgAedAARcWNjdXN0b21zdHJpbmdvaWRxAH4AaXQAEnFjY3V"
                    + "zdG9tc3RyaW5ndGV4dHEAfgBpdAAJcWNldHNpcGRzcHQACnFjZXRzaXR5cGVwdAAhdXNlY2VydGlmaWNhdGV0cmFuc3Bh"
                    + "cmVuY3lpbmNlcnRzcQB+ABV0ACB1c2VjZXJ0aWZpY2F0ZXRyYW5zcGFyZW5jeWlub2NzcHEAfgAVdAAldXNlY2VydGlma"
                    + "WNhdGV0cmFuc3BhcmVuY3lpbnB1Ymxpc2hlcnEAfgAVdAAXdXNlc3ViamVjdGRpcmF0dHJpYnV0ZXNxAH4AFXQAEnVzZW"
                    + "5hbWVjb25zdHJhaW50c3EAfgAVdAAddXNlYXV0aG9yaXR5aW5mb3JtYXRpb25hY2Nlc3NxAH4AFXQACWNhaXNzdWVyc3N"
                    + "xAH4AHAAAAAB3BAAAAAB4dAASdXNlZGVmYXVsdGNhaXNzdWVycQB+AB50ABx1c2VkZWZhdWx0b2NzcHNlcnZpY2Vsb2Nh"
                    + "dG9ycQB+AB50ABVvY3Nwc2VydmljZWxvY2F0b3J1cmlxAH4AaXQAD2N2Y2FjY2Vzc3JpZ2h0c3NxAH4ADQAAAAN0ABl1c"
                    + "2VkY2VydGlmaWNhdGVleHRlbnNpb25zc3EAfgAcAAAAAHcEAAAAAHh0AAlhcHByb3ZhbHNzcQB+AAU/QAAAAAAADHcIAA"
                    + "AAEAAAAAR+cgAwb3JnLmNlc2Vjb3JlLmNlcnRpZmljYXRlcy5jYS5BcHByb3ZhbFJlcXVlc3RUeXBlAAAAAAAAAAASAAB"
                    + "4cgAOamF2YS5sYW5nLkVudW0AAAAAAAAAABIAAHhwdAAKQUNUSVZBVEVDQXNxAH4ADf////9+cQB+AJl0AApSRVZPQ0FU"
                    + "SU9OcQB+AJ1+cQB+AJl0AApLRVlSRUNPVkVScQB+AJ1+cQB+AJl0ABBBRERFRElURU5ERU5USVRZcQB+AJ14AHQAHnVzZ"
                    + "XByaXZrZXl1c2FnZXBlcmlvZG5vdGJlZm9yZXEAfgAVdAAVdXNlcHJpdmtleXVzYWdlcGVyaW9kcQB+ABV0AB11c2Vwcm"
                    + "l2a2V5dXNhZ2VwZXJpb2Rub3RhZnRlcnEAfgAVdAAdcHJpdmtleXVzYWdlcGVyaW9kc3RhcnRvZmZzZXRzcgAOamF2YS5"
                    + "sYW5nLkxvbmc7i+SQzI8j3wIAAUoABXZhbHVleHEAfgAKAAAAAAAAAAB0ABhwcml2a2V5dXNhZ2VwZXJpb2RsZW5ndGhz"
                    + "cQB+AKgAAAAAA8JnAHQAJHVzZXNpbmdsZWFjdGl2ZWNlcnRpZmljYXRlY29uc3RyYWludHEAfgAVdAAYb3ZlcnJpZGFib"
                    + "GVleHRlbnNpb25vaWRzc3IAF2phdmEudXRpbC5MaW5rZWRIYXNoU2V02GzXWpXdKh4CAAB4cgARamF2YS51dGlsLkhhc2"
                    + "hTZXS6RIWVlri3NAMAAHhwdwwAAAACP0AAAAAAAAF0ABIxLjMuNi4xLjUuNS43LjEuMjR4dAAbbm9ub3ZlcnJpZGFibGV"
                    + "leHRlbnNpb25vaWRzc3EAfgCudwwAAAABP0AAAAAAAAB4dAAUdXNlY3VzdG9tZG5vcmRlcmxkYXBxAH4AFXgA"));
        final ObjectInputStream ois = new ObjectInputStream(bis);
        final CertificateProfile cannedCertificateProfile = (CertificateProfile) ois.readObject();
        final CertificateProfileData cannedData = new CertificateProfileData(918650336, "Acme TLS Server Certificate", cannedCertificateProfile);
        cannedData.setRowProtection("1:2:123:1ac180859e18ea7d48acecedf6ec06079f98ef63ded4c77748fed727cbac50491ed"
                + "6aec24644faf588565dac76d8a9cd359c3b273e151e789b3e9f04adc2785e61061051f424ccc24ab57181dd70894f"
                + "4437f9c0580a610e6bc5c9a22655bbe9cfa914625dcb2a084c946d4c32b9ca3b70ab7eab13959b4bd8d6b2d021a8f15e");

        cannedData.verifyData();
        log.trace("<certificateProfileCreatedInEjbca614Verifies");
    }

    /**
     * Test that a certificate profile created and signed in EJBCA 6.11 still verifies. The verification should
     * succeed on the first attempt since the signature was computed in the old "correct" way in <=EJBCA 6.11.
     */
    @Test
    public void certificateProfileCreatedInEjbca611Verifies() throws Exception {
        log.trace(">certificateProfileCreatedInEjbca611Verifies");
        assumeTrue(isDatabaseProtectionImplementationAvailable());

        final ByteArrayInputStream bis = new ByteArrayInputStream(
                Base64.decodeBase64("rO0ABXNyAD9vcmcuY2VzZWNvcmUuY2VydGlmaWNhdGVzLmNlcnRpZmljYXRlcHJvZmlsZS5DZXJ0aWZp"
                        + "Y2F0ZVByb2ZpbGWQAv2yYUWtSgIAAHhyACxvcmcuY2VzZWNvcmUuaW50ZXJuYWwuVXBncmFkZWFibGVEYXRhSGFzaE"
                        + "1hcOd8vFMpTFJHAgACWgAIdXBncmFkZWRMAARkYXRhdAAZTGphdmEvdXRpbC9MaW5rZWRIYXNoTWFwO3hwAHNyACJv"
                        + "cmcuY2VzZWNvcmUudXRpbC5CYXNlNjRHZXRIYXNoTWFwBxVvc8BHrukCAAB4cgAXamF2YS51dGlsLkxpbmtlZEhhc2"
                        + "hNYXA0wE5cEGzA+wIAAVoAC2FjY2Vzc09yZGVyeHIAEWphdmEudXRpbC5IYXNoTWFwBQfawcMWYNEDAAJGAApsb2Fk"
                        + "RmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAAwHcIAAABAAAAAG90AAd2ZXJzaW9uc3IAD2phdmEubGFuZy5GbG9hdN"
                        + "rtyaLbPPDsAgABRgAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHBCOAAAdAAEdHlwZXNyABFq"
                        + "YXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cQB+AAoAAAABdAALY2VydHZlcnNpb250AAZYNTA5dj"
                        + "N0AA9lbmNvZGVkdmFsaWRpdHl0AAIyeXQAHHVzZWNlcnRpZmljYXRldmFsaWRpdHlvZmZzZXRzcgARamF2YS5sYW5n"
                        + "LkJvb2xlYW7NIHKA1Zz67gIAAVoABXZhbHVleHAAdAAZY2VydGlmaWNhdGV2YWxpZGl0eW9mZnNldHQABC0xMG10AC"
                        + "N1c2VleHBpcmF0aW9ucmVzdHJpY3Rpb25mb3J3ZWVrZGF5c3EAfgAVdAAmZXhwaXJhdGlvbnJlc3RyaWN0aW9uZm9y"
                        + "d2Vla2RheXNiZWZvcmVzcQB+ABQBdAAdZXhwaXJhdGlvbnJlc3RyaWN0aW9ud2Vla2RheXNzcgATamF2YS51dGlsLk"
                        + "FycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAB3cEAAAAB3EAfgAacQB+ABpzcQB+ABQAcQB+AB5xAH4AHnEA"
                        + "fgAacQB+ABp4dAAVYWxsb3d2YWxpZGl0eW92ZXJyaWRlcQB+ABV0ABZhbGxvd2V4dGVuc2lvbm92ZXJyaWRlcQB+AB"
                        + "V0AA9hbGxvd2Rub3ZlcnJpZGVxAH4AFXQAFGFsbG93ZG5vdmVycmlkZWJ5ZWVpcQB+ABV0ABhhbGxvd2JhY2tkYXRl"
                        + "ZHJldm9rYXRpb25xAH4AFXQAFXVzZWNlcnRpZmljYXRlc3RvcmFnZXNxAH4AFAF0ABRzdG9yZWNlcnRpZmljYXRlZG"
                        + "F0YXEAfgAldAATc3RvcmVzdWJqZWN0YWx0bmFtZXEAfgAldAASdXNlYmFzaWNjb25zdHJhbnRzcQB+ACV0ABhiYXNp"
                        + "Y2NvbnN0cmFpbnRzY3JpdGljYWxxAH4AJXQAF3VzZXN1YmplY3RrZXlpZGVudGlmaWVycQB+ACV0ABxzdWJqZWN0a2"
                        + "V5aWRlbnRpZmllcmNyaXRpY2FscQB+AB50ABl1c2VhdXRob3JpdHlrZXlpZGVudGlmaWVycQB+ACV0AB5hdXRob3Jp"
                        + "dHlrZXlpZGVudGlmaWVyY3JpdGljYWxxAH4AHnQAGXVzZXN1YmplY3RhbHRlcm5hdGl2ZW5hbWVxAH4AJXQAHnN1Ym"
                        + "plY3RhbHRlcm5hdGl2ZW5hbWVjcml0aWNhbHEAfgAVdAAYdXNlaXNzdWVyYWx0ZXJuYXRpdmVuYW1lcQB+ACV0AB1p"
                        + "c3N1ZXJhbHRlcm5hdGl2ZW5hbWVjcml0aWNhbHEAfgAVdAAXdXNlY3JsZGlzdHJpYnV0aW9ucG9pbnRxAH4AFXQAHn"
                        + "VzZWRlZmF1bHRjcmxkaXN0cmlidXRpb25wb2ludHEAfgAedAAcY3JsZGlzdHJpYnV0aW9ucG9pbnRjcml0aWNhbHEA"
                        + "fgAedAAXY3JsZGlzdHJpYnV0aW9ucG9pbnR1cml0AAB0ABx1c2VjcmxkaXN0cmlidXRpb25wb2ludG9uY3JscQB+AB"
                        + "50AA51c2VmcmVzaGVzdGNybHEAfgAVdAAXdXNlY2FkZWZpbmVkZnJlc2hlc3RjcmxxAH4AHnQADmZyZXNoZXN0Y3Js"
                        + "dXJpcQB+ADZ0AAljcmxpc3N1ZXJxAH4ANnQAFnVzZWNlcnRpZmljYXRlcG9saWNpZXNxAH4AFXQAG2NlcnRpZmljYX"
                        + "RlcG9saWNpZXNjcml0aWNhbHEAfgAedAATY2VydGlmaWNhdGVwb2xpY2llc3NxAH4AHAAAAAB3BAAAAAB4dAAWYXZh"
                        + "aWxhYmxla2V5YWxnb3JpdGhtc3NxAH4AHAAAAAN3BAAAAAN0AANEU0F0AAVFQ0RTQXQAA1JTQXh0ABFhdmFpbGFibG"
                        + "VlY2N1cnZlc3NxAH4AHAAAAAF3BAAAAAF0AAxBTllfRUNfQ1VSVkV4dAATYXZhaWxhYmxlYml0bGVuZ3Roc3NxAH4A"
                        + "HAAAAA93BAAAAA9zcQB+AA0AAAAAc3EAfgANAAAAwHNxAH4ADQAAAOBzcQB+AA0AAADvc3EAfgANAAABAHNxAH4ADQ"
                        + "AAAYBzcQB+AA0AAAIAc3EAfgANAAACCXNxAH4ADQAABABzcQB+AA0AAAYAc3EAfgANAAAIAHNxAH4ADQAADABzcQB+"
                        + "AA0AABAAc3EAfgANAAAYAHNxAH4ADQAAIAB4dAAZbWluaW11bWF2YWlsYWJsZWJpdGxlbmd0aHEAfgBKdAAZbWF4aW"
                        + "11bWF2YWlsYWJsZWJpdGxlbmd0aHNxAH4ADQAAIAB0ABJzaWduYXR1cmVhbGdvcml0aG1wdAALdXNla2V5dXNhZ2Vx"
                        + "AH4AJXQACGtleXVzYWdlc3EAfgAcAAAACXcEAAAACXEAfgAlcQB+ACVxAH4AJXEAfgAVcQB+ABVxAH4AFXEAfgAVcQ"
                        + "B+ABVxAH4AFXh0ABVhbGxvd2tleXVzYWdlb3ZlcnJpZGVxAH4AFXQAEGtleXVzYWdlY3JpdGljYWxxAH4AJXQAE3Vz"
                        + "ZWV4dGVuZGVka2V5dXNhZ2VxAH4AJXQAEGV4dGVuZGVka2V5dXNhZ2VzcQB+ABwAAAACdwQAAAACdAARMS4zLjYuMS"
                        + "41LjUuNy4zLjJ0ABExLjMuNi4xLjUuNS43LjMuNHh0ABhleHRlbmRlZGtleXVzYWdlY3JpdGljYWxxAH4AFXQAE3Vz"
                        + "ZWRvY3VtZW50dHlwZWxpc3RxAH4AFXQAGGRvY3VtZW50dHlwZWxpc3Rjcml0aWNhbHEAfgAedAAQZG9jdW1lbnR0eX"
                        + "BlbGlzdHNxAH4AHAAAAAB3BAAAAAB4dAAMYXZhaWxhYmxlY2Fzc3EAfgAcAAAAAXcEAAAAAXNxAH4ADWJ9doJ4dAAO"
                        + "dXNlZHB1Ymxpc2hlcnNzcQB+ABwAAAAAdwQAAAAAeHQADnVzZW9jc3Bub2NoZWNrcQB+ABV0AA51c2VsZGFwZG5vcm"
                        + "RlcnEAfgAldAAQdXNlY3VzdG9tZG5vcmRlcnEAfgAVdAAUdXNlbWljcm9zb2Z0dGVtcGxhdGVxAH4AFXQAEW1pY3Jv"
                        + "c29mdHRlbXBsYXRldAAAdAANdXNlY2FyZG51bWJlcnEAfgAVdAAMdXNlY25wb3N0Zml4cQB+ABV0AAljbnBvc3RmaX"
                        + "hxAH4AdnQAEnVzZXN1YmplY3RkbnN1YnNldHEAfgAVdAAPc3ViamVjdGRuc3Vic2V0c3EAfgAcAAAAAHcEAAAAAHh0"
                        + "ABd1c2VzdWJqZWN0YWx0bmFtZXN1YnNldHEAfgAVdAAUc3ViamVjdGFsdG5hbWVzdWJzZXRzcQB+ABwAAAAAdwQAAA"
                        + "AAeHQAF3VzZXBhdGhsZW5ndGhjb25zdHJhaW50cQB+AB50ABRwYXRobGVuZ3RoY29uc3RyYWludHNxAH4ADQAAAAB0"
                        + "AA51c2VxY3N0YXRlbWVudHEAfgAVdAARdXNlcGtpeHFjc3ludGF4djJxAH4AHnQAFnVzZXFjc3RhdGVtZW50Y3JpdG"
                        + "ljYWxxAH4AHnQAFHVzZXFjc3RhdGVtZW50cmFuYW1lcQB+AHZ0AA91c2VxY3NlbWF0aWNzaWRxAH4AdnQAFXVzZXFj"
                        + "ZXRzaXFjY29tcGxpYW5jZXEAfgAedAAYdXNlcWNldHNpc2lnbmF0dXJlZGV2aWNlcQB+AB50ABN1c2VxY2V0c2l2YW"
                        + "x1ZWxpbWl0cQB+AB50ABBxY2V0c2l2YWx1ZWxpbWl0cQB+AIJ0ABNxY2V0c2l2YWx1ZWxpbWl0ZXhwcQB+AIJ0ABhx"
                        + "Y2V0c2l2YWx1ZWxpbWl0Y3VycmVuY3lxAH4AdnQAGHVzZXFjZXRzaXJldGVudGlvbnBlcmlvZHEAfgAedAAVcWNldH"
                        + "NpcmV0ZW50aW9ucGVyaW9kcQB+AIJ0ABF1c2VxY2N1c3RvbXN0cmluZ3EAfgAedAARcWNjdXN0b21zdHJpbmdvaWRx"
                        + "AH4AdnQAEnFjY3VzdG9tc3RyaW5ndGV4dHEAfgB2dAAJcWNldHNpcGRzcHQACnFjZXRzaXR5cGVwdAAhdXNlY2VydG"
                        + "lmaWNhdGV0cmFuc3BhcmVuY3lpbmNlcnRzcQB+ABV0ACB1c2VjZXJ0aWZpY2F0ZXRyYW5zcGFyZW5jeWlub2NzcHEA"
                        + "fgAVdAAldXNlY2VydGlmaWNhdGV0cmFuc3BhcmVuY3lpbnB1Ymxpc2hlcnEAfgAVdAAXdXNlc3ViamVjdGRpcmF0dH"
                        + "JpYnV0ZXNxAH4AFXQAEnVzZW5hbWVjb25zdHJhaW50c3EAfgAVdAAddXNlYXV0aG9yaXR5aW5mb3JtYXRpb25hY2Nl"
                        + "c3NxAH4AFXQACWNhaXNzdWVyc3NxAH4AHAAAAAB3BAAAAAB4dAASdXNlZGVmYXVsdGNhaXNzdWVycQB+AB50ABx1c2"
                        + "VkZWZhdWx0b2NzcHNlcnZpY2Vsb2NhdG9ycQB+AB50ABVvY3Nwc2VydmljZWxvY2F0b3J1cmlxAH4AdnQAD2N2Y2Fj"
                        + "Y2Vzc3JpZ2h0c3NxAH4ADQAAAAN0ABl1c2VkY2VydGlmaWNhdGVleHRlbnNpb25zc3EAfgAcAAAAAHcEAAAAAHh0AA"
                        + "lhcHByb3ZhbHNzcQB+AAU/QAAAAAAADHcIAAAAEAAAAAR+cgAwb3JnLmNlc2Vjb3JlLmNlcnRpZmljYXRlcy5jYS5B"
                        + "cHByb3ZhbFJlcXVlc3RUeXBlAAAAAAAAAAASAAB4cgAOamF2YS5sYW5nLkVudW0AAAAAAAAAABIAAHhwdAAKS0VZUk"
                        + "VDT1ZFUnNxAH4ADV6Q2dR+cQB+AKZ0ABBBRERFRElURU5ERU5USVRZc3EAfgANXpDZ1H5xAH4ApnQACkFDVElWQVRF"
                        + "Q0FzcQB+AA1ekNnUfnEAfgCmdAAKUkVWT0NBVElPTnNxAH4ADV6Q2dR4AHQAHnVzZXByaXZrZXl1c2FnZXBlcmlvZG"
                        + "5vdGJlZm9yZXEAfgAVdAAVdXNlcHJpdmtleXVzYWdlcGVyaW9kcQB+ABV0AB11c2Vwcml2a2V5dXNhZ2VwZXJpb2Ru"
                        + "b3RhZnRlcnEAfgAVdAAdcHJpdmtleXVzYWdlcGVyaW9kc3RhcnRvZmZzZXRzcgAOamF2YS5sYW5nLkxvbmc7i+SQzI"
                        + "8j3wIAAUoABXZhbHVleHEAfgAKAAAAAAAAAAB0ABhwcml2a2V5dXNhZ2VwZXJpb2RsZW5ndGhzcQB+ALgAAAAAA8Jn"
                        + "AHQAJHVzZXNpbmdsZWFjdGl2ZWNlcnRpZmljYXRlY29uc3RyYWludHEAfgAVdAAYb3ZlcnJpZGFibGVleHRlbnNpb2"
                        + "5vaWRzc3IAF2phdmEudXRpbC5MaW5rZWRIYXNoU2V02GzXWpXdKh4CAAB4cgARamF2YS51dGlsLkhhc2hTZXS6RIWV"
                        + "lri3NAMAAHhwdwwAAAABP0AAAAAAAAB4dAAbbm9ub3ZlcnJpZGFibGVleHRlbnNpb25vaWRzc3EAfgC+dwwAAAABP0"
                        + "AAAAAAAAB4dAAUdXNlY3VzdG9tZG5vcmRlcmxkYXBxAH4AFXgA"));
        final ObjectInputStream ois = new ObjectInputStream(bis);
        final CertificateProfile cannedCertificateProfile = (CertificateProfile) ois.readObject();
        final CertificateProfileData cannedData = new CertificateProfileData(1146818275, "cp", cannedCertificateProfile);
        cannedData.setRowProtection(
                "1:2:123:8246a06bade82bb93a6c814790a105b7f43c96e376c6f2cad22543b24326a5cdd616b6fd08897f7d3294d1bb6ba7"
                + "e61c457904fb7cd87a4f2514e64faa71838bc7c23b53b1c630a854989877f5f2c02f49c44185accf512c1fd1ae5fb0f945"
                + "c1eb482fc3247b616f438dfd510945c0982fffbdf98c50c01c3dca2ad965554405");

        cannedData.verifyData();
        log.trace("<certificateProfileCreatedInEjbca611Verifies");
    }
}
