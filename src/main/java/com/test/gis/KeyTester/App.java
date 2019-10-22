package com.test.gis.KeyTester;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.Enumeration;

import com.digt.trusted.jce.provider.DIGTProvider;

public class App
{
    public static void main( String[] args )
    {
		try {
			App app = new App();
			app.run();
		} catch (Exception e) {
			e.printStackTrace();
		}
    }

	public void log(String s) {
		System.out.println(s);
	}

	public void run() throws Exception {
		org.apache.xml.security.Init.init();

		String path = "FAT12\\XXXXXXXX_XXX\\xxxxxxxx.xxx\\XXXX";
		String password = "xxxxxxxx";

		Provider provider = DIGTProvider.class.newInstance();
		Security.addProvider(provider);

        KeyStore keyStore = KeyStore.getInstance("CryptoProCSPKeyStore", provider);

        keyStore.load(new ByteArrayInputStream("CurrentUser/My".getBytes(Charset.forName("UTF-8"))), password.toCharArray());

        log("Keystory type: " + keyStore.getType());
        log("Keystore provider: " + provider.getName());

        log("Private keys:");
        Enumeration<String> aliases = keyStore.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (keyStore.entryInstanceOf(alias, KeyStore.PrivateKeyEntry.class)) {
                log("Private key:");

                Key k = keyStore.getKey(alias, password.toCharArray());
                Certificate[] certs = keyStore.getCertificateChain(alias);
                for (Certificate cert : certs) {
                	log("cert public key algorithm:" + cert.getPublicKey().getAlgorithm());
                }
                log("Private key algorithm:"+k.getAlgorithm());

                PasswordProtection protection = new PasswordProtection(password.toCharArray());
                PrivateKeyEntry keyEntry = (PrivateKeyEntry) keyStore.getEntry(path, protection);
                if (keyEntry == null) {
                	log("Key not found");
                }
            }
        }
	}
}
