package threshold.mr04.data;

import java.io.Serializable;
import java.math.BigInteger;

public class Round1Message implements Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private final BigInteger mPrime;
    private final BigInteger ciphertext1;
    private final BigInteger ciphertext2;

    public Round1Message(BigInteger mPrime, BigInteger ciphertext1, BigInteger ciphertext2) {
        this.mPrime = mPrime;
        this.ciphertext1 = ciphertext1;
        this.ciphertext2 = ciphertext2;
    }

    public BigInteger getmPrime() {
        return mPrime;
    }

    public BigInteger getCiphertext1() {
        return ciphertext1;
    }

    public BigInteger getCiphertext2() {
        return ciphertext2;
    }

}
