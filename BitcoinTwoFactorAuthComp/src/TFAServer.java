import com.apple.dnssd.*;

import javax.net.ssl.*;
import javax.swing.*;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.Certificate;
import java.io.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Created by hkalodner on 11/6/14.
 */
public class TFAServer implements Runnable, RegisterListener {

    public static final String ServiceType = "_bitcointwofactor._tcp";
    private SSLServerSocket mSSLServerSocket;
    private TFAConnection mConnection;

    public static void main(String[] args) throws IOException {
        new TFAServer();
    }

    public TFAServer() {

        try {
            mSSLServerSocket = getSSLServerSocket();
            int listentingPort = mSSLServerSocket.getLocalPort();
            DNSSD.register(null, ServiceType, listentingPort, this);
        } catch (DNSSDException e) {
            e.printStackTrace();
        }

        new Thread(this).start();
    }

    public void operationFailed(DNSSDService service, int errorCode)
    {
        System.out.println("DNS-SD operation failed " + errorCode);
        System.exit(-1);
    }

    // If our name changes while we're running, we update window title.
    // In the event that we're registering in multiple domains (Wide-Area
    // DNS-SD) we'll use the local (mDNS) name for display purposes.
    public void serviceRegistered(DNSSDRegistration sd, int flags,
                                  String serviceName, String regType, String domain)
    {
        System.out.println("name = " + serviceName);
    }

    // Our run(  ) method just sits and waits for incoming connections
    // and hands each one off to a new thread to handle it.
    public void run(  )
    {
        try
        {
            while (true) {
                SSLSocket sslsocket = (SSLSocket) mSSLServerSocket.accept();
                if (sslsocket != null) {
                    System.out.println("Successfully accepted socket");
                    mConnection = new TFAConnection(sslsocket);
                }
            }
        }
        catch (Exception e) { e.printStackTrace(  ); }
    }

    public static SSLServerSocket getSSLServerSocket() {
        // Load CAs from an InputStream
        // (could be from a resource or ByteArrayInputStream or ...)
        System.setProperty("javax.net.ssl.keyStore","mysystem.jks");
        System.setProperty("javax.net.ssl.keyStorePassword","welcome");

        System.setProperty("javax.net.ssl.trustStore","mysystem.jks");
        System.setProperty("javax.net.ssl.trustStorePassword","welcome");
        char ksPass[] = "welcome".toCharArray();
        char ctPass[] = "welcome".toCharArray();

        //Create and load the Keystore
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream("mysystem.jks"), ksPass);
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(ks, ctPass);

            //Create the ServerSocket as an SSLServerSocket
            SSLContext secureSocket = SSLContext.getInstance("TLS");
            secureSocket.init(kmf.getKeyManagers(), null, null);
            SSLServerSocketFactory ssf = secureSocket.getServerSocketFactory();
            SSLServerSocket ssocket = (SSLServerSocket) ssf.createServerSocket(0);

            //This explicitly states TLS with 2-way authentication
            ssocket.setNeedClientAuth(false);
            return ssocket;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (KeyManagementException e) {
            e.printStackTrace();
        }
        return null;
    }
}