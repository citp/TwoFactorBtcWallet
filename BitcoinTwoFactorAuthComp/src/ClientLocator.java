import com.apple.dnssd.*;

import javax.swing.*;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.channels.ServerSocketChannel;

/**
 * Created by hkalodner on 11/5/14.
 */
public class ClientLocator extends JFrame implements BrowseListener {

    public static final String ServiceType = "_bitcointwofactor._tcp";
    private ServerSocketChannel mListentingChannel;
    private int mListentingPort;


    public static void main(String[] args)
    {
        Runnable runOnSwingThread = new Runnable(  )
        { public void run(  ) { new ClientLocator(); } };
        try { SwingUtilities.invokeAndWait(runOnSwingThread); }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    public ClientLocator() {
        setSize(200, 300);
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setVisible(true);
        try {
            DNSSD.browse(ServiceType, this);
        } catch (DNSSDException e) {
            e.printStackTrace();
        }
    }

    public void operationFailed(DNSSDService service, int errorCode)
    {
        System.out.println("DNS-SD operation failed " + errorCode);
        System.exit(-1);
    }

    // Our serviceFound and serviceLost callbacks just make Adder and
    // Remover objects that safely run on the event-dispatching thread
    // so they can modify the user interface
    public void serviceFound(DNSSDService browser, int flags, int ind,
                             String name, String type, String domain)
    {
        System.out.println("Found " + name + ", " + type + ", " + domain);
        ClientConnection con = new ClientConnection();
        try {
            DNSSD.resolve(0, ind, name, ServiceType, domain, con);
        } catch (DNSSDException e) {
            e.printStackTrace();
        }

    }

    public void serviceLost(DNSSDService browser, int flags, int ind,
                            String name, String regType, String domain)
    {
        System.out.println("Lost " + domain + " : " + name);
    }
}
