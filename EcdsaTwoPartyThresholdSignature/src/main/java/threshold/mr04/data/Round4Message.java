package threshold.mr04.data;

import java.io.Serializable;
import java.math.BigInteger;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class Round4Message implements Serializable {
    
	private static final long serialVersionUID = 2024431130585981353L;
	private final BigInteger u;
    private final BigInteger uPrime;
    private final BigInteger z1;
    private final BigInteger z2;
    private final BigInteger z3;
    private final byte[] yRaw;
    private final BigInteger e;
    private final BigInteger s1;
    private final BigInteger s2;
    private final BigInteger s3;
    private final BigInteger t1;
    private final BigInteger t2;
    private final BigInteger t3;
    private final BigInteger t4;
    private final BigInteger t5;
    private final BigInteger t6;

    public Round4Message(BigInteger u, BigInteger uPrime, BigInteger z1, BigInteger z2, BigInteger z3, ECPoint y,
            BigInteger e, BigInteger s1, BigInteger s2, BigInteger s3, BigInteger t1,
            BigInteger t2, BigInteger t3, BigInteger t4, BigInteger t5, BigInteger t6) {
        this.u = u;
        this.uPrime = uPrime;
        this.z1 = z1;
        this.z2 = z2;
        this.z3 = z3;
        this.yRaw = y.getEncoded();
        this.e = e;
        this.s1 = s1;
        this.s2 = s2;
        this.s3 = s3;
        this.t1 = t1;
        this.t2 = t2;
        this.t3 = t3;
        this.t4 = t4;
        this.t5 = t5;
        this.t6 = t6;
    }

    public BigInteger getU() {
        return u;
    }
    
    public BigInteger getUPrime() {
        return uPrime;
    }

    public BigInteger getZ1() {
        return z1;
    }

    public BigInteger getZ2() {
        return z2;
    }

    public BigInteger getZ3() {
        return z3;
    }

    public ECPoint getY(ECCurve curve) {
    	return curve.decodePoint(yRaw);
    }

    public BigInteger getE() {
        return e;
    }

    public BigInteger getS1() {
        return s1;
    }

    public BigInteger getS2() {
        return s2;
    }

    public BigInteger getS3() {
        return s3;
    }

    public BigInteger getT1() {
        return t1;
    }

    public BigInteger getT2() {
        return t2;
    }

    public BigInteger getT3() {
        return t3;
    }

    public BigInteger getT4() {
        return t4;
    }

    public BigInteger getT5() {
        return t5;
    }

    public BigInteger getT6() {
        return t6;
    }

}
