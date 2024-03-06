package com.hoddmimes.sshauth;

import com.sshtools.common.ssh.components.SshCipher;
import com.sshtools.common.ssh.components.jce.AES256Ctr;
import com.sshtools.common.ssh.components.jce.SHA256Digest;

import java.io.File;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;


public class ECSSHTest
{


    public static void main(String[] args) {
        ECSSHTest t = new ECSSHTest();
        try {t.test();}
        catch( Exception e) { e.printStackTrace(); }
    }

    private void test() throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        SSHKeyAuthorizationBC tClient, tServer;
        /* ======================================================
            Test to use SSH files with password
         ====================================================== */
        // Create and initialize "Client" using SSH private key file
        tClient = new SSHKeyAuthorizationBC();
        tClient.initClientSide( new File("id_rsa_with_password_foobar"), "foobar");

        // Create and initialize "server" using SSH public key file
        tServer = new SSHKeyAuthorizationBC();
        tServer.initServerSide( new File("id_rsa_with_password_foobar.pub" ));
        verificationTest( tClient, tServer, "SSH files \"id_rsa_with_password_foobar\"" );

        /* ======================================================
            Test to use SSH files without password
         ====================================================== */
        // Create and initialize "Client" using SSH private key file
        tClient = new SSHKeyAuthorizationBC();
        tClient.initClientSide( new File("id_rsa_without_password"), null);

        // Create and initialize "server" using SSH public key file
        tServer = new SSHKeyAuthorizationBC();
        tServer.initServerSide( new File("id_rsa_without_password.pub" ));
        verificationTest( tClient, tServer, "SSH files \"id_rsa_without_password\"" );

        /* ======================================================
            Test to use SSH files without password wih provided formate keys
         ====================================================== */
        // Create and initialize "Client" using SSH private key file
        tClient = new SSHKeyAuthorizationBC();
        tClient.initClientSide( new String(Files.readAllBytes(Paths.get("id_rsa_without_password")), StandardCharsets.UTF_8),null);

        // Create and initialize "server" using SSH public key file
        tServer = new SSHKeyAuthorizationBC();
        tServer.initServerSide( new String( Files.readAllBytes(Paths.get("id_rsa_without_password.pub")), StandardCharsets.UTF_8));
        verificationTest( tClient, tServer, "SSH keys as strings \"id_rsa_without_password\"" );


        /* ======================================================
            Test to use SSH files with password wih provided formate keys
         ====================================================== */
        // Create and initialize "Client" using SSH private key file
        tClient = new SSHKeyAuthorizationBC();
        tClient.initClientSide( new String(Files.readAllBytes(Paths.get("id_rsa_with_password_foobar")), StandardCharsets.UTF_8),"foobar");

        // Create and initialize "server" using SSH public key file
        tServer = new SSHKeyAuthorizationBC();
        tServer.initServerSide( new String( Files.readAllBytes(Paths.get("id_rsa_with_password_foobar.pub")), StandardCharsets.UTF_8));
        verificationTest( tClient, tServer, "SSH keys as strings \"id_rsa_with_password_foobar\"" );
    }

    private void verificationTest(SSHKeyAuthorizationBC client, SSHKeyAuthorizationBC server, String usageMessage) throws Exception
    {
        System.out.println("Start verification of " + usageMessage);
        // Establish a common secret key using Diffe-Hellman key exchange
        client.initAgreement( server.getAgreementPublicKey());
        server.initAgreement( client.getAgreementPublicKey());

        // Verify that client and server has agreed upon the same secret value
        byte[] client_secret_key = client.getCommonSecretKey();
        byte[] server_secret_key= server.getCommonSecretKey();

        if (server_secret_key.length != client_secret_key.length) {
            throw new Exception("Common secret key value length is not the same");
        }
        for (int i = 0; i < server_secret_key.length; i++) {
            if (server_secret_key[i] != client_secret_key[i]) {
                throw new Exception("Common secret key value is not the same at position " + i);
            }
        }

        // When a common secret key has been constructed using the Diffe-Hellman key exchange
        // an encrypted session can be established. In this test we will use the AES256Ctr implementation provided
        // by com.sshtools.common.ssh.components.jce;

            SecureChannel clientCipher = new SecureChannel( client_secret_key);
            SecureChannel serverCipher = new SecureChannel( server_secret_key);

            /*
             Now the server needs to verify that the client is in posetion of the private key
             */
            // Create and get a challange (128 bytes) encrypted with the SSH public key
            byte[] tEncryptedChallange = server.getEncryptedChallange(128);
            // encrypt and "send" the encrypted-challange to the client over the secure channel established
            byte[] tSrvChlData = serverCipher.encrypt( tEncryptedChallange );
            // the client need to the decrypt the encrypted data received from the server
            byte[] tCltChlData = clientCipher.decrypt( tSrvChlData );
            // the client must now decrypt the challange with its SSH private key
            byte[] tUncryptedChallange = client.decryptChallange( tCltChlData );
            // when having the uncrypted challange it should be sent back to server using the secure-channel
            tCltChlData = clientCipher.encrypt( tUncryptedChallange );
            // when the server receives the response from the client it needs to decrypt the response
            tUncryptedChallange = serverCipher.decrypt(tCltChlData);
            // When having the uncrypted challange from the client it needs to be verified against the generated challange
            if (!server.verifyChallange( tUncryptedChallange)) {
                throw new Exception("Failed to verify challange");
            }




            // At this point the client SSH keys has been verified, and we should be able to
            // use the established client/server secure channels established
            // Of cause the secure channel may be something else HTTPS or your own preferred implementation.
            // A server may have multiple public keys that it would like to test against
            System.out.println("Successfully verified " + usageMessage + "\n");;
    }


    class SecureChannel {
        private AES256Ctr encrypter, decrypter;

        SecureChannel( byte[] pKey ) {
            try {
               SHA256Digest mac = new SHA256Digest();
               mac.putBytes( pKey );
               byte[] iv = mac.doFinal();

                decrypter = new AES256Ctr();
                decrypter.init( SshCipher.DECRYPT_MODE, iv , pKey);

                encrypter = new AES256Ctr();
                encrypter.init( SshCipher.ENCRYPT_MODE, iv, pKey);
            }
            catch( Exception e) {
                throw new RuntimeException( e );
            }
        }

        byte[] encrypt( byte[] pData ) {
            try {
                byte[] tOutData = new byte[pData.length];
                encrypter.transform(pData, 0, tOutData, 0, pData.length);
                return tOutData;
            }
            catch( Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        byte[] decrypt( byte[] pData ) {
            try {
                byte[] tOutData = new byte[pData.length];
                decrypter.transform(pData, 0, tOutData, 0, pData.length);
                return tOutData;
            }
            catch( Exception e) {
                e.printStackTrace();
            }
            return null;
        }
    }
}
