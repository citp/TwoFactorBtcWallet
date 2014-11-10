package threshold.mr04;

import java.math.BigInteger;

public class PaillierPublicKey {
    
    public BigInteger N;
    public BigInteger g;
    
    public PaillierPublicKey(BigInteger N, BigInteger g) {
        this.N = N;
        this.g = g;
    }

}
