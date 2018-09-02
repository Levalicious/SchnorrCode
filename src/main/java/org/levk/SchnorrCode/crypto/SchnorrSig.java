package org.levk.SchnorrCode.crypto;

import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.util.Arrays;

import static org.levk.SchnorrCode.crypto.SchnorrKey.*;

public class SchnorrSig {
    private ECPoint R;
    private BigInteger s;

    public SchnorrSig(byte[] data) {
        /* Deserialize signature */
        try {
            this.R = liftPoint(Arrays.copyOfRange(data, 0, 32));
            this.s = bytesToBigInteger(Arrays.copyOfRange(data, 32, 64));
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse signature", e);
        }
    }

    public SchnorrSig(ECPoint R, BigInteger s) {
        this.R = R;
        this.s = s;
    }

    public ECPoint getR() {
        return R;
    }

    public byte[] getRBytes() {
        return bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32);
    }

    public BigInteger gets() {
        return s;
    }

    public byte[] getsBytes() {
        return bigIntegerToBytes(s, 32);
    }

    public byte[] toBytes() {
        return merge(bigIntegerToBytes(R.getAffineXCoord().toBigInteger(), 32), bigIntegerToBytes(s, 32));
    }
}