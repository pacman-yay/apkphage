/*
 * Universal Android SSL Pinning Bypass
 * Bypasses TrustManager, OkHTTP, and HttpsURLConnection
 */
setTimeout(function() {
    Java.perform(function () {
        console.log("[+] Injecting Universal SSL Unpinning...");

        // 1. TrustManager (Base Android API)
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'dev.apkphage.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () {return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
        try {
            SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                console.log('[+] Intercepted SSLContext.init() - Bypassing TrustManager');
                SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
            };
        } catch (err) {
            console.log("[-] SSLContext hook failed: " + err);
        }

        // 2. OkHTTP3
        try {
            var CertificatePinner = Java.use('okhttp3.CertificatePinner');
            CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, certs) {
                console.log('[+] Intercepted OkHTTP3 CertificatePinner.check() for ' + host);
                return;
            };
        } catch (err) {
            console.log("[-] OkHTTP3 hook failed: " + err);
        }

        // 3. HttpsURLConnection (HostnameVerifier)
        try {
            var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
            HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(hostnameVerifier) {
                console.log('[+] Intercepted HttpsURLConnection.setDefaultHostnameVerifier()');
                return;
            };
            HttpsURLConnection.setSSLSocketFactory.implementation = function(SSLSocketFactory) {
                console.log('[+] Intercepted HttpsURLConnection.setSSLSocketFactory()');
                return;
            };
            HttpsURLConnection.setHostnameVerifier.implementation = function(hostnameVerifier) {
                console.log('[+] Intercepted HttpsURLConnection.setHostnameVerifier()');
                return;
            };
        } catch (err) {
            console.log("[-] HttpsURLConnection hook failed: " + err);
        }
        
        console.log("[+] SSL Unpinning completely injected.");
    });
}, 0);
