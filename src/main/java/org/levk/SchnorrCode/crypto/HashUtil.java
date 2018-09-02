package org.levk.SchnorrCode.crypto;

import org.bouncycastle.jcajce.provider.digest.Blake2b;
import org.bouncycastle.jcajce.provider.digest.Keccak;

import java.security.MessageDigest;
import java.util.Arrays;

public class HashUtil {
    private static MessageDigest blake = new Blake2b.Blake2b256();
    private static MessageDigest keccak = new Keccak.Digest256();

    public static byte[] blake2(byte[] input) {
        blake.reset();
        return blake.digest(input);
    }

    public static byte[] sha3(byte[] input) {
        keccak.reset();
        return keccak.digest(input);
    }

    public static byte[] blake2omit12(byte[] input) {
        byte[] hash = blake2(input);
        return Arrays.copyOfRange(hash, 12, hash.length);
    }

    public static byte[] blake2ECC(byte[] input) {
        byte[] hash = blake2(input);
        return Arrays.copyOfRange(hash, 28, hash.length);
    }
}
