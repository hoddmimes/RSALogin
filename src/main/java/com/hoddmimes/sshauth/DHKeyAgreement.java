package com.hoddmimes.sshauth;


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


import com.sshtools.common.ssh.components.jce.SHA256Digest;
import java.math.BigInteger;
import java.security.SecureRandom;


public class DHKeyAgreement
{
    BigInteger y; // My selected private value
    BigInteger x; // Remote public value

    BigInteger p; // public prime value
    BigInteger g; // public exp value

    DHKeyAgreement( BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
        this.y = getRandomPrime( 256 );
    }


    private BigInteger getRandomPrime(int pBitLength) {
        return BigInteger.probablePrime(pBitLength, new SecureRandom());
    }

    public void setRemotePublicValue( BigInteger x) {
        this.x = x;
    }

    public BigInteger getSecretValue() {
        return x.modPow(y,p);
    }

    public BigInteger getPublicValue() {
        return g.modPow(y,p);
    }

    public byte[] getSecretKey( ) {
        try {
            SHA256Digest mac = new SHA256Digest();
            mac.putBytes(getSecretValue().toByteArray());
            return mac.doFinal();
        }
        catch( Exception e) {
           throw new RuntimeException(e);
        }
    }
}
