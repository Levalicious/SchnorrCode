package org.levk.SchnorrCode.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

import static org.levk.SchnorrCode.crypto.HashUtil.blake2;
import static org.levk.SchnorrCode.crypto.HashUtil.blake2omit12;

public class SchnorrKey {
    private static final ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
    private static final ECPoint G = ecSpec.getG();
    private static final BigInteger order = ecSpec.getN();
    private static final BigInteger p = bytesToBigInteger(Hex.decode("00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));


    private final byte[] privkey;
    private final ECPoint pubkey;
    private final byte[] pubkeybytes;

    public SchnorrKey() {
        BigInteger x = BigIntegers.createRandomInRange(BigInteger.ONE, order.subtract(BigInteger.ONE), new SecureRandom());
        this.pubkey = G.multiply(x).normalize();

        this.pubkeybytes = point_bytes(pubkey);

        this.privkey = bigIntegerToBytes(x, 32);
    }

    public byte[] getPrivkey() {
        return privkey;
    }

    public byte[] getAddress() {
        return blake2omit12(getPubkey());
    }

    public byte[] getPubkey() {
        return pubkeybytes;
    }

    public ECPoint getPubPoint() {
        return pubkey;
    }

    public static ECPoint liftPoint(byte[] x) throws Exception {
        if (x.length != 33) {
            throw new Exception("Input must be 33 bytes: 1 indicator byte & 32 bytes representing the number.");
        } else {
            return ecSpec.getCurve().decodePoint(x).normalize();
        }
    }

    public static byte[] point_bytes(ECPoint point) {
        if (point.getAffineYCoord().toBigInteger().getLowestSetBit() != 0) {
            return merge(Hex.decode("02"), bigIntegerToBytes(point.getAffineXCoord().toBigInteger(), 32));
        } else {
            return merge(Hex.decode("03"), bigIntegerToBytes(point.getAffineXCoord().toBigInteger(),32));
        }
    }

    public SchnorrKey(byte[] privKey) {
        this.privkey = privKey;

        this.pubkey = G.multiply(bytesToBigInteger(privKey)).normalize();

        this.pubkeybytes = point_bytes(pubkey);
    }

    public SchnorrSig sign(byte[] hash) {
        /* Hash private key & message hash, convert to int mod order */
        BigInteger k = bytesToBigInteger(blake2(merge(privkey, hash))).mod(order);

        /* Use k value as deterministic nonce for R point */
        ECPoint R = G.multiply(k).normalize();

        /* Checks if R is a quadratic residue (?) */
        while (jacobi(R.getAffineYCoord().toBigInteger()) != 1) {
            k = (order.subtract(k));
            R = G.multiply(k).normalize();
        }

        /* Hashes x-coord of R + public key point x coord + message hash, converts to int mod order */
        BigInteger e = bytesToBigInteger(blake2(merge(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32), pubkeybytes, hash))).mod(order);

        /* Returns R point + (k e*priv) mod order */
        return new SchnorrSig(R, k.add(e.multiply(bytesToBigInteger(privkey))).mod(order));
    }

    public static boolean verify(SchnorrSig sig, ECPoint PubKey, byte[] hash) {
        if (!ecSpec.getCurve().importPoint(PubKey).isValid()) {
            System.out.println("Failed cuz invalid point");
            return false;
        }

        if (!(bytesToBigInteger(Arrays.copyOfRange(sig.toBytes(), 0, 32)).compareTo(p) == -1)) {
            System.out.println("Failed cuz Rx greater than curve modulus");
            return false;
        }

        if (!(bytesToBigInteger(Arrays.copyOfRange(sig.toBytes(), 32, 64)).compareTo(order) == -1)) {
            System.out.println("Failed cuz s greater than curve order");
            return false;
        }

        BigInteger e = bytesToBigInteger(blake2(merge(Arrays.copyOfRange(sig.toBytes(), 0, 32), point_bytes(PubKey), hash))).mod(order);

        ECPoint R = G.multiply(bytesToBigInteger(Arrays.copyOfRange(sig.toBytes(), 32, 64))).normalize().subtract(PubKey.multiply(e).normalize()).normalize();

        if (R.isInfinity()) {
            System.out.println("Failed cuz R is point @ Infinity");
            return false;
        }

        if (jacobi(R.getAffineYCoord().toBigInteger()) != 1) {
            System.out.println("Failed cuz R jacobi thingy stuff");
            return false;
        }

        if (R.getAffineXCoord().toBigInteger().compareTo(bytesToBigInteger(Arrays.copyOfRange(sig.toBytes(), 0, 32))) != 0) {
            System.out.println("Failed cuz R doesn't match encoded R");
            return false;
        }

        return true;
    }

    public static boolean verify(byte[] sig, byte[] pubkey, byte[] hash) {
        if (sig.length != 64) {
            System.out.println("Bad sig length");
            return false;
        }

        if (pubkey.length != 33) {
            System.out.println("Bad pubkey length");
            return false;
        }

        if (hash.length != 32) {
            System.out.println("Bad hash length");
            return  false;
        }

        try {
            if (!ecSpec.getCurve().importPoint(liftPoint(pubkey)).isValid()) {
                System.out.println("Failed cuz invalid point");
                return false;
            }

            BigInteger r = bytesToBigInteger(Arrays.copyOfRange(sig, 0, 32));
            BigInteger s = bytesToBigInteger(Arrays.copyOfRange(sig, 32, 64));

            if (r.compareTo(p) != -1) {
                System.out.println("r value too big");
                return false;
            }

            if (s.compareTo(order) != -1) {
                System.out.println("s value too big");
                return false;
            }

            BigInteger e = bytesToBigInteger(blake2(merge(Arrays.copyOfRange(sig, 0, 32), pubkey, hash)));
            ECPoint R = G.multiply(s).normalize().add(liftPoint(pubkey).multiply(order.subtract(e)).normalize()).normalize();

            if (R == null) {
                System.out.println("R point didn't initialize");
                return false;
            }

            if (R.isInfinity()) {
                System.out.println("R is point at infinity");
                return false;
            }

            if (jacobi(R.getAffineYCoord().toBigInteger()) != 1) {
                System.out.println("Failed jacobi");
                return false;
            }

            if (R.getAffineXCoord().toBigInteger().compareTo(r) != 0) {
                System.out.println("Doesn't equal the R thingy");
                return false;
            }

            return  true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    private static int jacobi(BigInteger x) {
        return IntegerFunctions.jacobi(x, p);
    }

    /**
     * Cast hex encoded value from byte[] to BigInteger
     * null is parsed like byte[0]
     *
     * @param bb byte array contains the values
     * @return unsigned positive BigInteger value.
     */
    public static BigInteger bytesToBigInteger(byte[] bb) {
        return (bb == null || bb.length == 0) ? BigInteger.ZERO : new BigInteger(1, bb);
    }

    /**
     * @param arrays - arrays to merge
     * @return - merged array
     */
    public static byte[] merge(byte[]... arrays)
    {
        int arrCount = 0;
        int count = 0;
        for (byte[] array: arrays)
        {
            arrCount++;
            count += array.length;
        }

        // Create new array and copy all array contents
        byte[] mergedArray = new byte[count];
        int start = 0;
        for (byte[] array: arrays) {
            System.arraycopy(array, 0, mergedArray, start, array.length);
            start += array.length;
        }
        return mergedArray;
    }

    /**
     * The regular {@link BigInteger#toByteArray()} method isn't quite what we often need:
     * it appends a leading zero to indicate that the number is positive and may need padding.
     *
     * @param b the integer to format into a byte array
     * @param numBytes the desired size of the resulting byte array
     * @return numBytes byte long array.
     */
    public static byte[] bigIntegerToBytes(BigInteger b, int numBytes) {
        if (b == null)
            return null;
        byte[] bytes = new byte[numBytes];
        byte[] biBytes = b.toByteArray();
        int start = (biBytes.length == numBytes + 1) ? 1 : 0;
        int length = Math.min(biBytes.length, numBytes);
        System.arraycopy(biBytes, start, bytes, numBytes - length, length);
        return bytes;
    }
}