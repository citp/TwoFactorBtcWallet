package threshold.mr04;

import java.io.Serializable;
import java.math.BigInteger;

public class PaillierPublicKey implements Serializable {
    
	private static final long serialVersionUID = -8908799568285493051L;
	public BigInteger N;
    public BigInteger g;
    
    public PaillierPublicKey(BigInteger N, BigInteger g) {
        this.N = N;
        this.g = g;
    }

}
