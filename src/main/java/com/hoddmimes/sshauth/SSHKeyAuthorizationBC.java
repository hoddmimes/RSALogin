package com.hoddmimes.sshauth;


import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import javax.crypto.*;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

/**
 * This class provides and implements a component allowing SSH (RSA) keys to be used to authorize an abitrary
 * client / server connection. The connection schema works as follows.
 *
 * - The client uploads or makes it public key available to the server. It is assumed that the client is in posetion
 *   of the public and private key.
 *
 * - The client and server establish and encrypted session with a secret symetric key. The symetric key is created by the client and  server using the
 *   public ssh key and Diffe-Hellman key exchange schema, see https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
 *
 * - With the created symetric a encrypted communication between the client server is established.
 *
 * - When the connection is established the server needs to verify that the client is posetion of the private ssh key.
 *   This is accomplished by the server is generated a random string 128 bytes.  The string is encrypted with AES256CTR using the
 *   public SSH key. The encrypted random string is sent to the client that need to decrypt the string with its private SSH key.
 *   After the string is decrypted the string is retuned to the client for verification. The client will only be able to decrypt
 *   the string if the client has the private SSH key.
 */


public class SSHKeyAuthorizationBC {
    private byte[] mChallange;
    private KeyAgreement mKeyAgreement;
    private KeyPair mECKeyPair;
    private PublicKey mCounterPartyPublicKey;


    public void initClientSide( String pKeyString, String pPassword ) throws IOException, GeneralSecurityException {
        PEMParser pemParser = new PEMParser(new StringReader(pKeyString));

        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
        KeyPair kp;

        if (object instanceof PEMEncryptedKeyPair) {
            // Encrypted key - we will use provided password
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(pPassword.toCharArray());
            kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
        } else {
            // Unencrypted key - no password needed
            PEMKeyPair ukp = (PEMKeyPair) object;
            kp = converter.getKeyPair(ukp);
        }

        KeyPairGenerator tKeyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec tKeyParams = new ECGenParameterSpec("secp256r1");
        tKeyPairGenerator.initialize(tKeyParams);

        mECKeyPair = tKeyPairGenerator.generateKeyPair();

    }

    public void initClientSide( File pKeyFile, String passwordPhrase )  throws IOException, GeneralSecurityException {
        initClientSide( new String(Files.readAllBytes(pKeyFile.toPath()), StandardCharsets.UTF_8), passwordPhrase );
    }

    public void initServerSide( String pKeyString) throws GeneralSecurityException {
        KeyPairGenerator tKeyPairGenerator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec tKeyParams = new ECGenParameterSpec("secp256r1");
        tKeyPairGenerator.initialize(tKeyParams);
        mECKeyPair = tKeyPairGenerator.generateKeyPair();
    }

    public void initServerSide( File pKeyFile) throws IOException, GeneralSecurityException {
        String tKeyStrArr[] = new String(Files.readAllBytes(pKeyFile.toPath()), StandardCharsets.UTF_8).split(" ");
        initServerSide( tKeyStrArr[1]);
    }


    public byte[] getAgreementPublicKey() {
        return mECKeyPair.getPublic().getEncoded();
    }

    public void initAgreement( byte[] pEncodedECPublicKey ) throws GeneralSecurityException
    {
        X509EncodedKeySpec tKeySpec = new X509EncodedKeySpec(pEncodedECPublicKey);
        KeyFactory tKeyFactory = KeyFactory.getInstance("EC");
        this.mCounterPartyPublicKey =  tKeyFactory.generatePublic(tKeySpec);


        this.mKeyAgreement = KeyAgreement.getInstance("ECDH");
        this.mKeyAgreement.init( this.mECKeyPair.getPrivate());
        this.mKeyAgreement.doPhase( mCounterPartyPublicKey,  true );

    }

    public byte[] getCommonSecretKey() {
       return this.mKeyAgreement.generateSecret();
    }


    public byte[] encryptKey(PublicKey pPublicKey, byte[] pPlainData) throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, pPublicKey);
        return cipher.doFinal(pPlainData);

    }

    public byte[] decryptKey(PrivateKey pPrivateKey, byte[] pEncryptedData)  throws GeneralSecurityException
    {
        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, pPrivateKey);
        return  cipher.doFinal(pEncryptedData);
    }

    public byte[] decrypt(PublicKey key, byte[] ciphertext)  throws GeneralSecurityException
    {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(ciphertext);
    }

    public byte[] getEncryptedChallange(int pSize) throws Exception{
        this.mChallange = new byte[ pSize ];
        SecureRandom tRandom = new SecureRandom();
        tRandom.nextBytes( this.mChallange );

       // KeyFactory tKeyFactor = KeyFactory.getInstance("RSA");
       // PublicKey tPubKey = tKeyFactor.generatePublic( new RSAPublicKeySpec( mECKeyPair.getPublic().getq, mSshPubKey.getPublicExponent()));

        return encryptKey(this.mCounterPartyPublicKey, this.mChallange);

    }

    public byte[] decryptChallange(byte[] pEncryptedChallange) throws GeneralSecurityException {
        return this.decryptKey( mECKeyPair.getPrivate(), pEncryptedChallange );
    }

    public boolean verifyChallange( byte[] pDecryptedChallangeFromClient ) {
        if (pDecryptedChallangeFromClient.length != this.mChallange.length) {
            return false;
        }
        for (int i = 0; i < this.mChallange.length; i++) {
            if (this.mChallange[i] != pDecryptedChallangeFromClient[i]) {
                return false;
            }
        }
        return true;
    }
}
