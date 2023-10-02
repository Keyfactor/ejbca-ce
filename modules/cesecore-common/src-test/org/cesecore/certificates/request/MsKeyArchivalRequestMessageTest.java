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
package org.cesecore.certificates.request;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.certificate.request.MsKeyArchivalRequestMessage;
import org.junit.Test;

import com.keyfactor.util.CryptoProviderTools;

public class MsKeyArchivalRequestMessageTest {
    
    private static final String SAMPLE_REQUEST = "308208a906092a864886f70d010702a082089a30820896020103310b300906052b0e0"
            + "3021a0500308203e506082b06010505070c02a08203d7048203d3308203cf3081a030819d020102060a2b0601040182370a0a013"
            + "1818b3081880201003003020101317e302306092b0601040182371515311604147746e7e66bb597a67d08bf6e059c79e16dd66b8"
            + "3305706092b0601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f6"
            + "6742e636f6d0c154a444f4d4353435c61646d696e6973747261746f720c076365727472657130820324a08203200201013082031"
            + "9308202820201003023310f300d0603550403130654657374434e3110300e060355040a1307546573744f726730819f300d06092"
            + "a864886f70d010101050003818d0030818902818100dab2cc813700c9c8a0903da0f6b7a76880bf43441962fd9b713249c0b0a34"
            + "554d1e524c1cde3e6458a2de53fefcd7eebbc68de7488117661f37765c69c54ee546df9e59bc7ec8215bd6b15889793ec0d0aefa"
            + "85ede0ce794e07de73d44a4771dbdd803dfbfb489a1883c8572e336967ce07fe4ac848a696e02690be453fb2c950203010001a08"
            + "201b4301a060a2b0601040182370d0203310c160a362e302e353336312e323042060a2b0601040182370d0201313430321e26004"
            + "3006500720074006900660069006300610074006500540065006d0070006c0061007400651e080055007300650072305706092b0"
            + "601040182371514314a30480201090c237669636833642e6a646f6d6373632e6e74746573742e6d6963726f736f66742e636f6d0"
            + "c154a444f4d4353435c61646d696e6973747261746f720c07636572747265713074060a2b0601040182370d02023166306402010"
            + "11e5c004d006900630072006f0073006f0066007400200045006e00680061006e006300650064002000430072007900700074006"
            + "f0067007200610070006800690063002000500072006f00760069006400650072002000760031002e003003010030818206092a8"
            + "64886f70d01090e31753073301706092b0601040182371402040a1e08005500730065007230290603551d2504223020060a2b060"
            + "1040182370a030406082b0601050507030406082b06010505070302300e0603551d0f0101ff0404030205a0301d0603551d0e041"
            + "6041415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300d06092a864886f70d0101050500038181006ac9bc0cf7675e9161c78"
            + "ce7df37dc5fcc59cb38c071e61748cbf1d615f28161a330a8242f5d661094d3813445dffa3963ffc617a84ae545f9e814e2aaf4e"
            + "50cde845cf279c5e4419180b975d50c0df708c2adc790be8ff51f9d47e4b750ffaf40b6e21a9986d864dce2d4e41d82c66eab458"
            + "c7be3b5dcd8feaf9978cb1b7086300030003182049930820495020103801415bbba05358d0b21fb5db0f4a38fe3bf0f2ce0c5300"
            + "906052b0e03021a0500a03e301706092a864886f70d010903310a06082b06010505070c02302306092a864886f70d01090431160"
            + "414e088afba3f9bde527ff0887fced97debfa363f72300d06092a864886f70d01010105000481804505b61926013cc202172d9e1"
            + "d194df8ff4358e5544a24525b93e636005bbaaebfbc70d9c7f5d149e9e36ebdb7ac33c9147a81b59eb1a97c2287588b9028874f8"
            + "65b016ecb6fde4a6689e6e5bcaed259b5882381a552a071f0b0d457b8ac64fca03b7bbd8a5e571a711c4705708f27bc7a25beda7"
            + "910d083e08ac3f8d1ff513aa182039b3082039706092b060104018237150d318203883082038406092a864886f70d010703a0820"
            + "375308203710201003181ea3081e70201003050304231123010060355040a13094d6963726f736f6674312c302a0603550403132"
            + "34a444f4d435343204c6f6e67686f726e20456e746572707269736520526f6f74204341020a488a9b22000000000a39300d06092"
            + "a864886f70d0101010500048180960b583191d1fdd1ee45ccfa7a368ca09fb52df2a07def463b1a33a3bf861f00fb3b237cdb504"
            + "e5303e9c147a0186e4bba4a63df419395e6d56b03b117363adba12870f814c45d9e5e4414ae4947e22f357c9e8d9245c9fbe0bc3"
            + "8c9d674cdd93eaf70664476b9943c980b717a5a363ba72d45aa3d816eaf42a89631b1a76d263082027d06092a864886f70d01070"
            + "1301406082a864886f70d030704086cd44389e15a7fc380820258fae61aa513fcae9caefc78fe0b8f0698dcc5f3fd71e29a17488"
            + "65f30edcc4631a90ebead68ff6cfe7ecf6bfdeb647cde6eafe1a9956782388e0c9011f0fb976489701fdd38b3fddf73bf90e39f2"
            + "b11d664798ec3571264fea37c47958860c2193f454cbb48273f1db3b45c800161a4b677b27e22039418181b38e86ef01379c219f"
            + "54e43f5131ea035a9a9fdf2cf14ab2ab41618c0b6fd43d8a9672ee1a7d587a27d8460ecfe441c74cc2c7a9c2272a5d944d154185"
            + "bfc6bfef08bfd09dbe76100fe2abb421c549099df83f1915d22076fcc908445206fc3ed97b243adae5eabdcab69f857aefbb37b4"
            + "e1381b134a0171774e921d1a76870d6f69639924fe26f88ca6d318db267043e39234d1eefcbc8ef34ded1a02a95c3aec792ee136"
            + "cdeeb72e02cbb7b721d03df60c5bfae61bbf7742a0f1855c1c83652cfbf2c5b7704d7615524b85ce13851dd909d6bfd55644d7bf"
            + "045b660f998f1026a74841b4f9016945924988c84c0459f9bea120ebff3ac629f254e1281f5b5f9a0fb3add3883b87753672104b"
            + "6b2bf580cdf64b9da6cd51391a1e4dc007a527e9e6be1ee8ab4eb6349babc605a5de21f62949ee1e7773e12c607d0cb5bd4e33b6"
            + "5ac0ce0cd413af1072f3b8dea07fbe9bdcde0ba1f93767cac5276f48224eaddf8b4cff3a8cdbfe8d7fa9281bc549486533edd218"
            + "5344660ddc0af797887e2a322e52d6cb250211482260b369a0bd0897c93f763671e72ea2470916c68902fb6e687f4e7f0d1eec87"
            + "c1b15a5a978d24d10362ad4e67494c267d02f987815e735ac1e723101baae7e6e7c5154693c5cbd023289392fffdb58644971dfc"
            + "7f8fb";
    
    private static final String USER_ENROLL_REQ = "MIILxgYJKoZIhvcNAQcCoIILtzCCC7MCAQMxCzAJBgUrDgMCGgUAMIID5AYIKwYBBQUHDAKgggPW\n"
            + "BIID0jCCA84wRDBCAgECBgorBgEEAYI3CgoBMTEwLwIBADADAgEBMSUwIwYJKwYBBAGCNxUVMRYE\n"
            + "FHTq+BCMi8bi+6comXW0QM4pPQN/MIIDgKCCA3wCAQEwggN1MIICXQIBADAAMIIBIjANBgkqhkiG\n"
            + "9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxyefeFHvL2mMbgWOxaK1AzOWZJxD7uHRxjShFfqPg2YrLF2O\n"
            + "QtAPHDw+qlpPIVpS2UWMKM3vdi379Khq8kQUqjREZN+Z74e8M9SY6gHatWRvIruuVqvwTf6j5NR9\n"
            + "iATJq/SkvYD9myciGMkBkDRW9GF+wyXyIZKKr1/wwkpV/Fy0cScM1FeHUYRNBbha9Z4AY9ss22rT\n"
            + "ud5zd1zOxH9L4ORU2VKLLkEkAbyhYrw+MQ+2qTuxa4/HFsEQkZYHOaWAkdTgGxxIZlWToVx7Iixw\n"
            + "TxJ2dJMvv7erL7X32WTFPae4gnT9SAYXJlG3Y8E6qwWjW9g9vFDmfwtrs967U1Gz+QIDAQABoIIB\n"
            + "LjCCASoGCSqGSIb3DQEJDjGCARswggEXMD4GCSsGAQQBgjcVBwQxMC8GJisGAQQBgjcVCIWfoX+C\n"
            + "gJ5Kg6WFGYXI6iaE/JsggQCF9M9h7O17AgFkAgIAhzApBgNVHSUEIjAgBggrBgEFBQcDAgYIKwYB\n"
            + "BQUHAwQGCisGAQQBgjcKAwQwDgYDVR0PAQH/BAQDAgWgMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYB\n"
            + "BQUHAwIwCgYIKwYBBQUHAwQwDAYKKwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3\n"
            + "DQMCAgIAgDAOBggqhkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFIT2\n"
            + "cd3X4rhRDxPdRi2c7VyUqvIuMA0GCSqGSIb3DQEBBQUAA4IBAQC9qxJGCaLa1AzsprRYeAYfHNac\n"
            + "pyYBaKpQ2PfMENWJrasFveiVWznnZ97xr3TIEy7ameqKFjIcBuVxfs6wYOceYc3336dlfgtja5AQ\n"
            + "YxITfcS5jQnuBm/It7B+HUk7HhtnAJYvMoDd9a6hTMK2FTjwNGGnqiOKio77AV2frGOcoJMThFrG\n"
            + "shmmxs6RfGHs3sGrV2PkV6wP9/kW+PqxAExATwdnyAYiDnMYnaYJ0TU/DNlfAYTKYtHEMeAvNs3/\n"
            + "oAWHqyNip3je77YwGBFpNOxIGZj3HHjq/+iDuUKhyMJQWblRPlyBDZaDF8nrcly0UwhJ4F23X+CL\n"
            + "zBAAPCkr3KleMAAwADGCB7cwggezAgEDgBSE9nHd1+K4UQ8T3UYtnO1clKryLjAJBgUrDgMCGgUA\n"
            + "oD4wFwYJKoZIhvcNAQkDMQoGCCsGAQUFBwwCMCMGCSqGSIb3DQEJBDEWBBQzyRIZsqNBxOo6TnRN\n"
            + "a0UZOTccCjANBgkqhkiG9w0BAQEFAASCAQA2oKo1eN4a6AhBK1L/+hEuylnhd5XuPywyPTRNL/6Y\n"
            + "YFSkDLuju3s8mdhKubjBywLrcYmaIEkA+993p5fIgLDZMga6dgjR4lWdIIKUiM8emgGkXEUaNY0/\n"
            + "WbJa7Oy0LkAPk0RZLCx1jx5SWRuEdGd09lXQj4300QR+WA/9m/YAS7sTYbAWq+GHJjEyq8FeSTC/\n"
            + "K6Ya2hadsNsPbjo6fxYln1wPQCilCGPBvd02gywzHytpUr2aSih32Lqc8BgKjAfQsU9/f/TwYDzv\n"
            + "rpDQ/dnmjqKrhsO7zGZEabNREnzg/ByWb51hOyiMbOaW1ziACZIxlcQevb0aXZhVownZZGEzoYIG\n"
            + "ODCCBjQGCSsGAQQBgjcVDTGCBiUwggYhBgkqhkiG9w0BBwOgggYSMIIGDgIBADGCAUYwggFCAgEA\n"
            + "MCowEjEQMA4GA1UEAwwHSXNzdWVyMgIUV94OYm2LhjYpuvwHNneFoeIxlzcwDQYJKoZIhvcNAQEB\n"
            + "BQAEggEACrB20EQZHUFzmCa8dTjeOu4UQmqqxoMPYBmhfVRbo4TOg1M9skACm0t8GCz4BZOFLhLt\n"
            + "3YRtKaqtsRruX/8BoiXgPE2ZHIafxuAlV/lE87n3QmONPyDHa4Oxpi/nr1uRPZunsQtQabdwg/iI\n"
            + "Dnfj5IE88j/eFsR/9ASqvXydxc1yDdy3w+uRdKCFpUpVN4r5AJbBnTtv5Qi/af7WYpAd3R9VHD9x\n"
            + "HEkVr4QMxUQdKFyKttsh2Eazwp8DqxdAwpLZbX6owsjjKRmfEh0NJ5/mYgSHn54oIR0mkh0OV2eX\n"
            + "b2Ldc8HtzfdM5PB+VjMCaVGbfA/OQ1dZ0XhGCItJswvvUjCCBL0GCSqGSIb3DQEHATAUBggqhkiG\n"
            + "9w0DBwQIhFSQv9FSE4+AggSYAFS2f2KP/is70pDZ/FkMdgA4gOn9ytWg4PxnO3A3XPnOcaz7o2d3\n"
            + "Rsm+wYkjMrh40X1uF3iPbJ+Rq90UHaAiP2EX/5d8KZxWW5crLc2FC3IPmW2LhoF2Ev6wGDA+VDVy\n"
            + "47r2SbOLF8od9L0Hi42We/cBrWzKSkKIWXcA5Nml06TCT3N+8FAjMB5YsnMTTK7gpQFFaJc9xma5\n"
            + "tLxTtYhN7SVK/EvpiRn2HMVQHv5fU61q9YJzCPENOIBSMf4jqMBw4dzpEZ8uzLz2osiC3KQLzdhF\n"
            + "Hkhe1spVe2aSlhdTb05JM0gHOA8MV5X8D6ViGGwX96zE8bI+dPZQMy10rL01KcwUgStAWAOu4uK2\n"
            + "N7j60uFXPYWgoaxF/BN5T6dQkbrnjJCQ98ppMbvo489e+WQKHmSKiLurrPo/E6zlZIJjOd2ALGfc\n"
            + "aODFOnNyh0PLp4W7WYKTCNxC8sKs1BDyVXm7B1Jwls1eG38+g6uzRPGDqZ/Ya8SMNX5ar3Q8MY4m\n"
            + "LxY7daxkxMa9FaOuprHVVW+VUtw2/YiBeHMwjevD2K8jjpV1BZ61TOMsddpoKNZj5fKmnQZXc+9H\n"
            + "zLX5gAko7oAQLuIfvYKCSvfzA+uAes6TFnTRipOa35xTygHK+aReAZrF3m+Jo85R2WfhV1ExnIUi\n"
            + "0DHEgEaKO+IxegAIjvun7zb0VvCeGcxvhGBwxPQ09bO13l5/L8LwIIUlW0+gd2aCfCXrwXl2eu9J\n"
            + "wodCnxd2XyEwmYTgbYJcnmpWH0STBIfUFy0VZxyOOaKJcF716LtddeZLw4M1P4tgv9ncT2kU+VpB\n"
            + "PmndzanSActIuFUln3TyFHtv/dugBS2KW2XbbboPlbLhE/yoNU0VYhd/j5jMfxeLiRDEKJe0ZcEt\n"
            + "yANHV0GCLoWc0o6kI3eTvKyl8D2FVurHHer8MCBHtrVxdf31/VHyfn03DJkylpwyBzP6ZOOSH3Uy\n"
            + "lKlD6B7S7ZdzZvMOfh/PCEKDFuVSOdbk2m+E6MoXwFWpPZ8t0m9WDwKPMa/Lp8jZprhhiMOVKp4V\n"
            + "mNxRVg9qnsnNO8WC1IjD/18XHWnNACK4IezQpIJt7cbV1Fd7LJG6RrbsEW5BZUK6FSErUXVM6LX5\n"
            + "KRRHyzrEUMOZag2ZH9RZU8KuolaOoXYjlHrPTD6ve7NSb4vkqfd7z7kqmqIC2wYEInzUV7kUU9Cz\n"
            + "M9BiFokCz+OI6xQlj7beZADYx8P+DIwS9EYHYYeDIbflkDAsMctRBePup/VdLp0c6CusfB2wxzpj\n"
            + "cPQTEJUYX4y2vV/pEbB7Q2dceA857Drk4pJLuEfxqzD8rIA1ldVkB7tXH4Fxdp7ldiHajBOzSgsc\n"
            + "PsCyKZy+nrKAClmcW6s6IIFEvOSKEAhfqZjwJT6mJe1Eib+XZZXnfwaxmlJdSuVaEeGevBwcWOd3\n"
            + "90q7jQ8J8cUntumeRHzf6zupN1d2dtofzfmaK/b8NGuJykPmbCTESRGEVvvi0p4i368rjt6Khapn\n"
            + "uIgC30ELUt0UuRV+igTa9fWviHv4D+cFkdJ7mEAG+Z64sN1rfzaBQyj9/qSXK1yTfqfqR7jW";
    
    @Test
    public void testSmoke() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Hex.decode(SAMPLE_REQUEST));
        assertTrue(msg.verify());
        assertEquals("CN=TestCN,O=TestOrg", msg.getRequestDN());
    }
    
    @Test
    public void testUserEnroll() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        MsKeyArchivalRequestMessage msg = new MsKeyArchivalRequestMessage(Base64.decode(USER_ENROLL_REQ));
        assertTrue(msg.verify());
        assertEquals("", msg.getRequestDN()); // ?? AD look up
        assertNotNull(msg.getRequestPublicKey()); 
        
        String encodedPrivateKey = "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDRTiJtDwsRgozw\n"
                + "atZb4/X/HNB/xaOdiSukZRkJ5tNVOEuWV5fjYxALQcnuSW+uUHkwYyniZWO527Ct\n"
                + "lDEJ55TsI/PSXLJ7kFJCiAD4IpkaUyZ7XXpkmWd6SA7jp2EACIc8UIBJaMTuLpmL\n"
                + "ElgrDnu58Rwz652lbqPKqOYLFjkNr/y+JEtrOog8Lk+UPhsUPmXlx940RvWTkfHT\n"
                + "+K7FQC/tFO+4D5boonrH1VtJFd51ZDxsFDhrl2v3yuV8M3AAar516Td8DGe6Tqb6\n"
                + "88LYI4wTVcEBNFkR4ITC8d6721vR5rkihuzvB+XtYGZVlCekEySuM7dA6PcxZ5O6\n"
                + "evmhMGBHAgMBAAECggEAQ4kVJaB9f0xjIq4udZ8EQKlxA1Fn3kyk9toiLqY62Zwd\n"
                + "E6k22smboy46tHcgoJvZxsmweZsihxWCmDehbSM608k0AtQjSSiDynDs8yPix/I9\n"
                + "j//VHsG6+GNo3n8jFuopjMYi5sz2Ai6qH4wvQ9FcDd7lLUGg8ADXu+wssjYc+bOS\n"
                + "NyY9M7tn2oxj6cZkJW5sVgV7EekkAg21o2XB7EJ4NCudKtXmPrqI55G7f6/g1ekK\n"
                + "/+5G09dNqpRLFcWJphZVuU2n526EG6qIySLniFClwgvod/qK8hqgqINAGSOouDIO\n"
                + "OW3zKUlnBvWq4rn8nWFzt+UjdO42byRcUU0h9U13tQKBgQD4UvvXkzl9ASsuZUTD\n"
                + "P++NDLRNiAy+wx2Ch6k2ak4wR/8VfiJPK9HWofGMWSk0bpJjDgX1yf6u7fl0i+mD\n"
                + "+7+odrwaWG5xbGgSKKYJDwcBHRBRMuH1EIs0drydv0qW0HtTffzLplOx0ehyHk+9\n"
                + "OpXEaPlGxrgxdlXWAEsoCyAhqwKBgQDXxmO5s7DVmfTxG8UpOSmU3HfkhsTRI7Yb\n"
                + "jB3RyEB7fmvCPSJYk1MD8RNgzbuE/aagKSSa2K1tct/rALu5vxheiM4UO+1JTpnj\n"
                + "6HeqPSIovMilzmTzOUY4Z53+aropaJoULnYckmeUqqZy8vXna6NERu/crI45+Xpz\n"
                + "4OutQ0oX1QKBgFxpXWmDU4COn8g7TZSvxXEjSjIUMFIJgIDkBXfHpeNX17ji4Ne/\n"
                + "we5zA9YsFCZ8A6QzQsqOamYlD5Fsw/EnDdMepK/VOvyg0DX5xJhYbE3gyAK/wdEW\n"
                + "YAedLGI0Hwjy+wI+P4Z2Fm11ZWCaoSgVlkiqnCHXsBJQLG9gWpfDVCjTAoGAZ0r8\n"
                + "gHBpzcc2v5lIp/RKWI22AzsUyv1qdwN7XuqbG8MoOMLlRzu3eOKWITg7dW2rr24i\n"
                + "rNHfK87bLHecZk35j3+0D3GkpPwwpS6q4l8DlDbTYrRMFTcsy2Gm+50B40LEx7Z6\n"
                + "KjFXzo5mwg5W82LOtKe0uZINP+mS2hgpGjdlJ8UCgYBrkGcASe18yKscrWis02bx\n"
                + "3d+ror5tdATqmuJDJR31g/lSpC3w+sBvOleHcXkX36LSxZUqZyaHJowNoXYathbs\n"
                + "tgNgD2tp2hDBEHdJOcx5Vo7HGHRSAbJjeSBtjc8kJuSVmEvUNBST5Tt5DWzcOloJ\n"
                + "SSPpWa3QgFphkWUYxVi2Gw==";
        
        PrivateKey exchangePrivKey = null;
        try {
            KeyFactory kf = KeyFactory.getInstance("RSA");
            exchangePrivKey = kf.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(encodedPrivateKey)));
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        String encryptedData = "0ab076d044191d41739826bc7538de3aee14426aaac6830f6019a17d545ba384ce83533db240029b4b7c1"
                + "82cf80593852e12eddd846d29aaadb11aee5fff01a225e03c4d991c869fc6e02557f944f3b9f742638d3f20c76b83b1a62"
                + "fe7af5b913d9ba7b10b5069b77083f8880e77e3e4813cf23fde16c47ff404aabd7c9dc5cd720ddcb7c3eb9174a085a54a55"
                + "378af90096c19d3b6fe508bf69fed662901ddd1f551c3f711c4915af840cc5441d285c8ab6db21d846b3c29f03ab1740c29"
                + "2d96d7ea8c2c8e329199f121d0d279fe66204879f9e28211d26921d0e5767976f62dd73c1edcdf74ce4f07e56330269519b"
                + "7c0fce435759d17846088b49b30bef52";
        
        Cipher encCipher = Cipher.getInstance("RSA");
        encCipher.init(Cipher.DECRYPT_MODE, exchangePrivKey);
        byte[] encryptedBytes = encCipher.doFinal(Hex.decode(encryptedData));
        System.out.println(Hex.toHexString(encryptedBytes));
        
        final SecretKey key = new SecretKeySpec(encryptedBytes, "DESede");
        final IvParameterSpec iv = new IvParameterSpec(Hex.decode("845490bfd152138f"));
        final Cipher decipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        decipher.init(Cipher.DECRYPT_MODE, key, iv);
        
        String cbcEncrypted = "0054b67f628ffe2b3bd290d9fc590c76003880e9fdcad5a0e0fc673b70375cf9ce71acfba3677746c9bec1"
                + "892332b878d17d6e17788f6c9f91abdd141da0223f6117ff977c299c565b972b2dcd850b720f996d8b86817612feb01830"
                + "3e543572e3baf649b38b17ca1df4bd078b8d967bf701ad6cca4a4288597700e4d9a5d3a4c24f737ef05023301e58b27313"
                + "4caee0a5014568973dc666b9b4bc53b5884ded254afc4be98919f61cc5501efe5f53ad6af5827308f10d38805231fe23a8"
                + "c070e1dce9119f2eccbcf6a2c882dca40bcdd8451e485ed6ca557b66929617536f4e49334807380f0c5795fc0fa562186c"
                + "17f7acc4f1b23e74f650332d74acbd3529cc14812b405803aee2e2b637b8fad2e1573d85a0a1ac45fc13794fa75091bae7"
                + "8c9090f7ca6931bbe8e3cf5ef9640a1e648a88bbabacfa3f13ace564826339dd802c67dc68e0c53a73728743cba785bb59"
                + "829308dc42f2c2acd410f25579bb07527096cd5e1b7f3e83abb344f183a99fd86bc48c357e5aaf743c318e262f163b75ac"
                + "64c4c6bd15a3aea6b1d5556f9552dc36fd88817873308debc3d8af238e9575059eb54ce32c75da6828d663e5f2a69d0657"
                + "73ef47ccb5f9800928ee80102ee21fbd82824af7f303eb807ace931674d18a939adf9c53ca01caf9a45e019ac5de6f89a3"
                + "ce51d967e15751319c8522d031c480468a3be2317a00088efba7ef36f456f09e19cc6f846070c4f434f5b3b5de5e7f2fc2"
                + "f02085255b4fa07766827c25ebc179767aef49c287429f17765f21309984e06d825c9e6a561f44930487d4172d15671c8e"
                + "39a289705ef5e8bb5d75e64bc383353f8b60bfd9dc4f6914f95a413e69ddcda9d201cb48b855259f74f2147b6ffddba005"
                + "2d8a5b65db6dba0f95b2e113fca8354d1562177f8f98cc7f178b8910c42897b465c12dc803475741822e859cd28ea42377"
                + "93bcaca5f03d8556eac71deafc302047b6b57175fdf5fd51f27e7d370c9932969c320733fa64e3921f753294a943e81ed"
                + "2ed977366f30e7e1fcf08428316e55239d6e4da6f84e8ca17c055a93d9f2dd26f560f028f31afcba7c8d9a6b86188c3952a"
                + "9e1598dc51560f6a9ec9cd3bc582d488c3ff5f171d69cd0022b821ecd0a4826dedc6d5d4577b2c91ba46b6ec116e416542b"
                + "a15212b51754ce8b5f9291447cb3ac450c3996a0d991fd45953c2aea2568ea17623947acf4c3eaf7bb3526f8be4a9f77bc"
                + "fb92a9aa202db0604227cd457b91453d0b333d062168902cfe388eb14258fb6de6400d8c7c3fe0c8c12f4460761878321b"
                + "7e590302c31cb5105e3eea7f55d2e9d1ce82bac7c1db0c73a6370f4131095185f8cb6bd5fe911b07b43675c780f39ec3ae"
                + "4e2924bb847f1ab30fcac803595d56407bb571f8171769ee57621da8c13b34a0b1c3ec0b2299cbe9eb2800a599c5bab3a2"
                + "08144bce48a10085fa998f0253ea625ed4489bf976595e77f06b19a525d4ae55a11e19ebc1c1c58e777f74abb8d0f09f1c"
                + "527b6e99e447cdfeb3ba937577676da1fcdf99a2bf6fc346b89ca43e66c24c449118456fbe2d29e22dfaf2b8ede8a85aa6"
                + "7b88802df410b52dd14b9157e8a04daf5f5af887bf80fe70591d27b984006f99eb8b0dd6b7f36814328fdfea4972b5c937"
                + "ea7ea47b8d6";

        // final byte[] encData = new
        // sun.misc.BASE64Decoder().decodeBuffer(message);
        final byte[] plainText = decipher.doFinal(Hex.decode(cbcEncrypted));
        System.out.println(Hex.toHexString(plainText));
                
        //msg.decryptPrivateKey("BC", exchangePrivKey); // same result
    }

}
