package threshold.mr04.data;

import java.io.Serializable;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

public class Round2Message implements Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private final byte[] rawBob;

    public Round2Message(ECPoint rBob) {
    	this.rawBob = rBob.getEncoded();
    }

    public ECPoint getrBob(ECCurve curve) {
    	return curve.decodePoint(rawBob);
    }

}
