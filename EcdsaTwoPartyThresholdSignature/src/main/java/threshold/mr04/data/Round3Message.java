package threshold.mr04.data;

import java.io.Serializable;
import java.math.BigInteger;

import org.spongycastle.math.ec.ECPoint;

public class Round3Message implements Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private final ECPoint r;
    private final BigInteger z1;
    private final BigInteger z2;
    private final ECPoint y;
    private final BigInteger e;
    private final BigInteger s1;
    private final BigInteger s2;
    private final BigInteger s3;
    private final BigInteger t1;
    private final BigInteger t2;
    private final BigInteger t3;
    private final BigInteger t4;



    public Round3Message(ECPoint r, BigInteger z1, BigInteger z2, ECPoint y, BigInteger e,
            BigInteger s1, BigInteger s2, BigInteger s3, BigInteger t1, BigInteger t2,
            BigInteger t3, BigInteger t4) {
        this.r = r;
        this.z1 = z1;
        this.z2 = z2;
        this.y = y;
        this.e = e;
        this.s1 = s1;
        this.s2 = s2;
        this.s3 = s3;
        this.t1 = t1;
        this.t2 = t2;
        this.t3 = t3;
        this.t4 = t4;

    }

    public ECPoint getR() {
        return r;
    }

    public BigInteger getZ1() {
        return z1;
    }

    public BigInteger getZ2() {
        return z2;
    }

    public ECPoint getY() {
        return y;
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

}
