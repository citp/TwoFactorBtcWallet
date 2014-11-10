package threshold.mr04.data;

import java.io.Serializable;

import org.spongycastle.math.ec.ECPoint;

public class Round2Message implements Serializable {
    
    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    private final ECPoint rBob;

    public Round2Message(ECPoint rBob) {
        this. rBob = rBob;
    }

    public ECPoint getrBob() {
        return rBob;
    }

}
