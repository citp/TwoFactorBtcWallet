import com.apple.dnssd.DNSSDService;
import com.apple.dnssd.ResolveListener;
import com.apple.dnssd.TXTRecord;

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SocketChannel;

/**
 * Created by hkalodner on 11/5/14.
 */
public class ClientConnection implements ResolveListener, Runnable {

    private String mHost;
    private int mPort;
    private SocketChannel mChannel;

    public void operationFailed(DNSSDService service, int errorCode)
    {
        System.out.println("DNS-SD operation failed " + errorCode);
        System.exit(-1);
    }

    // When serviceResolved is called, we send our name to the other end
    // and then fire off our thread to start receiving the opponent's clicks.
    public void serviceResolved(DNSSDService resolver, int flags, int ifIndex,
                                String fullName, String theHost, int thePort, TXTRecord txtRecord)
    {
        System.out.println("Resolved " + fullName + ", " + theHost + ", " + thePort);
        mHost = theHost;
        mPort = thePort;
        String msg = "HELLOOOOOO!";
        try
        {
            InetSocketAddress socketAddress = new InetSocketAddress(mHost, mPort);
            mChannel = SocketChannel.open(socketAddress);
            ObjectOutputStream oos = new ObjectOutputStream(mChannel.socket().getOutputStream());

            oos.writeObject(msg);
            System.out.println("Printed to channel");
            new Thread(this).start(  );
        }
        catch (Exception e) { e.printStackTrace(  ); }

        resolver.stop(  );
    }

    public void run(  )
    {
        try
        {
            System.out.println("Receiving from channel");
            ObjectInputStream ois = new ObjectInputStream(mChannel.socket().getInputStream());
            while (true)
            {
                String msg =  (String) ois.readObject();
                System.out.println("Got message: " + msg);
            }
        }
        catch (Exception e) { } // Connection reset by peer!
    }
}
