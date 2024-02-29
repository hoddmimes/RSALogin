package com.hoddmimes.sshauth;


import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshKeyUtils;
import com.sshtools.common.ssh.components.*;


import javax.crypto.*;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;

import java.security.*;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;

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


public class SSHKeyAuthorization {
    private DHKeyAgreement mAgreement;
    private byte[] mChallange;
    private SshRsaPublicKey mSshPubKey;
    private SshKeyPair mSshPrvKeyPair;


    public void initClientSide( String pKeyString, String passwordPhrase ) throws IOException, InvalidPassphraseException {
        this.mSshPrvKeyPair = SshKeyUtils.getPrivateKey( pKeyString, passwordPhrase);
        this.mSshPubKey = null;

        SshRsaPublicKey tPubKey = (SshRsaPublicKey) mSshPrvKeyPair.getPublicKey();
        mAgreement = new DHKeyAgreement( tPubKey.getModulus(), tPubKey.getPublicExponent());

    }

    public void initClientSide( File pKeyFile, String passwordPhrase ) throws IOException, InvalidPassphraseException {
        this.mSshPrvKeyPair = SshKeyUtils.getPrivateKey( pKeyFile, passwordPhrase);
        this.mSshPubKey = null;
        SshRsaPublicKey tPubKey = (SshRsaPublicKey) mSshPrvKeyPair.getPublicKey();
        mAgreement = new DHKeyAgreement( tPubKey.getModulus(), tPubKey.getPublicExponent());
    }

    public void initServerSide( String pKeyString) throws IOException {
        this.mSshPubKey = (SshRsaPublicKey) SshKeyUtils.getPublicKey(pKeyString);
        this.mSshPrvKeyPair = null;
        mAgreement = new DHKeyAgreement( mSshPubKey.getModulus(), mSshPubKey.getPublicExponent());
    }

    public void initServerSide( File pKeyFile) throws IOException {
        this.mSshPubKey = (SshRsaPublicKey) SshKeyUtils.getPublicKey(pKeyFile);
        this.mSshPrvKeyPair = null;
        mAgreement = new DHKeyAgreement( mSshPubKey.getModulus(), mSshPubKey.getPublicExponent());
    }


    private void init( BigInteger p, BigInteger g) {
        mAgreement = new DHKeyAgreement(p, g);
    }

    BigInteger getpublicDHValue() {
        return mAgreement.getPublicValue();
    }

    public void setRemotePublicDHValue( BigInteger v) {
        mAgreement.setRemotePublicValue(v);
    }

    public BigInteger getSecretValue() {
       return  mAgreement.getSecretValue();
    }

    public byte[] getSecretKey() {
        return mAgreement.getSecretKey();
    }


    //Alice and Bob publicly agree to use a modulus p = 23 and base g = 5 (which is a primitive root modulo 23).
    //
    // Alice select y value = 5
    // g**y mod p -> 5**5 mod 23 -> 3125 mod 23 = 20
    // Alice share value (x) 20 with Bob
    //
    // Bob select y value = 3
    // g**y mod p -> 5**3 mod 23 -> 125 mod 23 = 10
    // Bob share value (x) 10 with Alice
    //
    // Bob secret key = x**y mod p --> 20**3 mod 23 --> 8000 mod 23 --> 19
    // Alice secret key = x**y mod p --> 10**5 mod 23 --> 100000 mod 23 --> 19


    public byte[] encryptKey(PublicKey key, byte[] plaintext) throws NoSuchPaddingException,NoSuchAlgorithmException,InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext);
    }

    public byte[] decryptKey(PrivateKey key, byte[] ciphertext)  throws NoSuchPaddingException,NoSuchAlgorithmException,InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(ciphertext);
    }

    public byte[] decrypt(PublicKey key, byte[] ciphertext)  throws NoSuchPaddingException,NoSuchAlgorithmException,InvalidKeyException, IllegalBlockSizeException, BadPaddingException
    {
            Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return cipher.doFinal(ciphertext);
    }

    public byte[] getEncryptedChallange(int pSize) throws Exception{
        this.mChallange = new byte[ pSize ];
        SecureRandom tRandom = new SecureRandom();
        tRandom.nextBytes( this.mChallange );

        KeyFactory tKeyFactor = KeyFactory.getInstance("RSA");
        PublicKey tPubKey = tKeyFactor.generatePublic( new RSAPublicKeySpec( mSshPubKey.getModulus(), mSshPubKey.getPublicExponent()));

        return encryptKey( tPubKey, this.mChallange);
    }

    public byte[] decryptChallange(byte[] pEncryptedChallange) throws Exception {
            PrivateKey tPrvKey = mSshPrvKeyPair.getPrivateKey().getJCEPrivateKey();
            return this.decryptKey( tPrvKey, pEncryptedChallange );
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
