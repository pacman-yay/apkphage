Java.perform(function () {
    // Hook Cipher.doFinal - catches decryption of hidden payloads,
    // exactly like Cghiqeqs.dc() did with assets/116adbd0
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload("[B").implementation = function (input) {
        var result = this.doFinal(input);
        console.log("[Cipher.doFinal] input length: " + input.length +
                     " output length: " + result.length);
        // Uncomment to dump decrypted bytes to a file via Frida's fs access
        // or send() them back to your Python controller for saving.
        return result;
    };

    // Hook DexClassLoader / in-memory dex loading - flags the
    // ClassLoader-injection technique from Cghiqeqs.inj()
    try {
        var InMemoryDexClassLoader = Java.use("dalvik.system.InMemoryDexClassLoader");
        InMemoryDexClassLoader.$init.overload(
            "java.nio.ByteBuffer", "java.lang.ClassLoader"
        ).implementation = function (buffer, parent) {
            console.log("[InMemoryDexClassLoader] payload DEX loaded into memory, size: " +
                         buffer.capacity());
            return this.$init(buffer, parent);
        };
    } catch (e) {
        console.log("InMemoryDexClassLoader hook skipped: " + e);
    }

    // Hook SmsManager, if present in a given sample
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String", "java.lang.String",
            "android.app.PendingIntent", "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, sent, delivered) {
            console.log("[SmsManager.sendTextMessage] to=" + dest + " text=" + text);
            return this.sendTextMessage(dest, sc, text, sent, delivered);
        };
    } catch (e) {
        console.log("SmsManager hook skipped: " + e);
    }
});
