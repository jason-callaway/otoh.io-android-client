package io.otoh.otohio;

import android.app.Activity;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Bundle;
import android.os.Environment;
import android.os.SystemClock;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.CheckBox;

import org.json.JSONObject;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.openpgp.PGPPublicKey;
import org.spongycastle.openpgp.PGPPublicKeyRing;
import org.spongycastle.openpgp.PGPSecretKeyRing;
import org.spongycastle.util.encoders.Base64;
import org.spongycastle.util.encoders.Hex;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Vector;
import java.util.concurrent.Executor;


public class GenIdentityActivity extends Activity {

    private Executor e = AsyncTask.SERIAL_EXECUTOR;

    private ProgressDialog pd;
    private CheckBox cb;

    private String username;
    private String accessKey;
    private String nickname;
    private String email;
    private String password;
    
    private String dsCSR;
    private String keCSR;
    
    private String dsCert;
    private String keCert;

    private String fingerprint;

    private Integer updateCounter = new Integer(0);

    private DBUtils dbUtils = new DBUtils(GenIdentityActivity.this);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_gen_identity);

        setTitle("Generating Your Identity");

        Intent i = getIntent();
        username = i.getStringExtra("username");
        accessKey = i.getStringExtra("access_key");
        nickname = i.getStringExtra("nickname");
        email = i.getStringExtra("email");
        password = i.getStringExtra("password");

        Security.addProvider(new BouncyCastleProvider());

        //This won't work if the user suspends the activity...

        // Do all of the things
        new AsyncTask<String, Vector, String>() {

            @Override
            protected void onPreExecute() {
                pd = new ProgressDialog(GenIdentityActivity.this);
                pd.setTitle("Processing...");
                pd.setMessage("Stand by");
                pd.setCancelable(false);
                pd.setMax(13);
                pd.setIndeterminate(false);
                pd.setProgressStyle(ProgressDialog.STYLE_HORIZONTAL);
                pd.setProgressNumberFormat(null);
                pd.show();
            }

            @Override protected void onProgressUpdate(Vector... values){
                pd.setProgress(new Integer((Integer) values[0].get(0)).intValue());
                pd.setMessage(new String((String)values[0].get(1)));
            }

            protected void updateProgress(String update){
                Vector v = new Vector();
                updateCounter++;
                v.addElement(new Integer(updateCounter.intValue()));
                v.addElement(new String(update));
                publishProgress(v);
            }

            @Override
            protected String doInBackground(String... arg) {

                nickname = arg[0];
                otoh o = new otoh(getString(R.string.otoh_api_ca));
                //Vector v;
                String alias;
                Calendar cal = Calendar.getInstance();
                Date now = cal.getTime();
                cal.add(Calendar.YEAR, 10);
                Date end = cal.getTime();
                try {
                    MessageDigest md = MessageDigest.getInstance("MD5");

                    // generate DS key pair
                    updateProgress("Generating RSA key pair for DS certificate");
                    alias  = "ds-" + nickname;
                    KeyPair dskp = o.generateRSAKeyPair();
                    PublicKey dspub = dskp.getPublic();
                    byte[] dspubDigest = md.digest(new String(Base64.encode(dspub.getEncoded())).getBytes());
                    String dsFingerprint = new String(Base64.encode(dspubDigest));

                    //generate KE key pair
                    updateProgress("Generating RSA key pair for KE certificate");
                    alias = "ke-" + nickname;
                    KeyPair kekp = o.generateRSAKeyPair();
                    PublicKey kepub = dskp.getPublic();
                    byte[] kepubDigest = md.digest(new String(Base64.encode(kepub.getEncoded())).getBytes());
                    String keFingerprint = new String(Base64.encode(kepubDigest));

                    //generate a PGP key pair
                    updateProgress("Generating PGP key pair");
                    alias = "ke-" + nickname;
                    // TODO: add password edittext
                    Vector pgpkp = o.generatePGPKeyPair(nickname, email, password);
                    PGPPublicKeyRing pgppkr = (PGPPublicKeyRing)pgpkp.elementAt(0);
                    PGPPublicKey pk = pgppkr.getPublicKey();
                    fingerprint = new String(Hex.encode(pk.getFingerprint()));

                    // Generate DS CSR
                    updateProgress("Generating DS CSR");
                    // Some of these steps happen too fast for the user to take note. We'll sleep
                    // for one second just so they can read the message.
                    SystemClock.sleep(1000);
                    alias = "ds-" + nickname;
                    dsCSR = o.generateCSR(dskp, username, email, "ds", fingerprint);


                    // Generate KE CSR
                    updateProgress("Generating KE CSR");
                    SystemClock.sleep(1000);
                    alias = "ke-" + nickname;
                    keCSR = o.generateCSR(kekp, username, email, "ke", fingerprint);

                    // Submit DS CSR
                    updateProgress("Submitting DS CSR");
                    SystemClock.sleep(1000);
                    alias = "ds-" + nickname;

                    Log.i("++++debug", "about to submit ds csr");
                    JSONObject certJson;
                    certJson = o.createUserCertificate(username, dsCSR, accessKey, nickname);
                    dsCert = certJson.getString("new cert");
                    Log.i("++++debug", "dsCert: " + dsCert);

                    // Submit KE CSR
                    updateProgress("Submitting KE CSR");
                    SystemClock.sleep(1000);
                    alias = "ke-" + nickname;

                    // This one is a bit different.  The DS cert can be set with one-way SSL, but
                    // the KE cert requires two-say, so we need to generate a new keystore with
                    // the otoh.io CA certs and the new DS cert.
                    String keystorePassword = password;
                    byte[] byteCert = Base64.decode(dsCert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
                    X509Certificate dsx509cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(byteCert));
                    KeyStore keystore = KeyStore.getInstance("BKS", "SC");
                    keystore.load(null, keystorePassword.toCharArray());
                    keystore.setCertificateEntry("dscert-" + nickname, dsx509cert);
                    keystore.setKeyEntry("dskey-" + nickname, dskp.getPrivate(), keystorePassword.toCharArray(), new X509Certificate[]{dsx509cert});

                    certJson = o.createCertificate(keystore, keystorePassword, username, keCSR, accessKey, nickname);
                    keCert = certJson.getString("new cert");
                    Log.i("++++debug", "keCert: " + keCert);

                    // Install DS CA Chain
                    updateProgress("Creating DS p12");
                    SystemClock.sleep(1000);
                    alias = "ds-" + nickname;
                    String dsp12filename = alias + ".p12";

                    // In order to create a p12 with the full CA chain, we need to first generate
                    // byte arrays of the root and signing CAs
                    byte[] signingCaBytes = Base64.decode(getString((R.string.otoh_api_ca)).replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
                    X509Certificate signingCa = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(signingCaBytes));
                    byte[] rootCaBytes = Base64.decode(getString((R.string.otoh_root_ca)).replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
                    X509Certificate rootCa = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(rootCaBytes));

                    KeyStore p12 = KeyStore.getInstance("PKCS12", "SC");
                    p12.load(null, null);

                    byte[] dsCertBytes = Base64.decode(dsCert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
                    X509Certificate dsx509Cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(dsCertBytes));

                    X509Certificate[] chain = new X509Certificate[3];
                    chain[0] = dsx509Cert;
                    chain[1] = signingCa;
                    chain[2] = rootCa;

                    // Now that we have a cert chain, we have to add in the private key for the
                    // DS cert.
                    p12.setKeyEntry(alias, dskp.getPrivate(), keystorePassword.toCharArray(), chain);
                    FileOutputStream p12Stream = getApplicationContext().openFileOutput(dsp12filename, Context.MODE_PRIVATE);
                    p12.store(p12Stream, keystorePassword.toCharArray());
                    p12Stream.flush();
                    p12Stream.close();

                    // Install KE CA Chain
                    updateProgress("Creating KE p12");
                    SystemClock.sleep(1000);
                    alias = "ke-" + nickname;
                    String kep12filename = alias + ".p12";

                    p12 = KeyStore.getInstance("PKCS12", "SC");
                    p12.load(null, null);

                    byte[] keCertBytes = Base64.decode(keCert.replaceAll("-----BEGIN CERTIFICATE-----", "").replaceAll("-----END CERTIFICATE-----", ""));
                    X509Certificate kex509Cert = (X509Certificate) CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(keCertBytes));

                    chain = new X509Certificate[3];
                    chain[0] = kex509Cert;
                    chain[1] = signingCa;
                    chain[2] = rootCa;

                    p12.setKeyEntry(alias, kekp.getPrivate(), keystorePassword.toCharArray(), chain);
                    p12Stream = getApplicationContext().openFileOutput(kep12filename, Context.MODE_PRIVATE);
                    p12.store(p12Stream, keystorePassword.toCharArray());
                    p12Stream.flush();
                    p12Stream.close();

                    // Copy p12 files to world-readable location
                    updateProgress("Placing p12 files in Documents");
                    SystemClock.sleep(1000);
                    File worldDir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "otoh.io");
                    worldDir.mkdirs();
                    File identityDir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS), "otoh.io/" + nickname);
                    identityDir.mkdirs();
                    File dsp12 = new File(getApplicationContext().getFilesDir(), dsp12filename);
                    File kep12 = new File(getApplicationContext().getFilesDir(), dsp12filename);
                    File dsout = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS) + "/otoh.io/" + nickname + "/", dsp12filename);
                    File keout = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS) + "/otoh.io/" + nickname + "/", kep12filename);

                    copy(dsp12, dsout);
                    copy(kep12, keout);

                    // Copy PGP key rings to world-readable location
                    updateProgress("Placing PGP keyrings in Documents");
                    SystemClock.sleep(1000);
                    String pkrname = "pgp-" + nickname + ".pkr";
                    String skrname = "pgp-" + nickname + ".skr";

                    BufferedOutputStream pkrbuff = new BufferedOutputStream(getApplicationContext().openFileOutput(pkrname, Context.MODE_PRIVATE));
                    PGPPublicKeyRing pkr = (PGPPublicKeyRing)pgpkp.get(0);
                    pkr.encode(pkrbuff);
                    pkrbuff.close();

                    BufferedOutputStream skrbuff = new BufferedOutputStream(getApplicationContext().openFileOutput(skrname, Context.MODE_PRIVATE));
                    PGPSecretKeyRing skr = (PGPSecretKeyRing)pgpkp.get(1);
                    skr.encode(skrbuff);
                    skrbuff.close();

                    File pkrin = new File(getApplicationContext().getFilesDir(), pkrname);
                    File skrin = new File(getApplicationContext().getFilesDir(), skrname);
                    File pkrout = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS) + "/otoh.io/" + nickname + "/", pkrname);
                    File skrout = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOCUMENTS) + "/otoh.io/" + nickname + "/", skrname);

                    copy(pkrin, pkrout);
                    copy(skrin, skrout);

                    // Last step is to populate our SQLite database
                    updateProgress("Updating Database");
                    SystemClock.sleep(1000);
                    HashMap<String, String> map = new HashMap<String, String>();
                    map.put("identitiesName", username);
                    map.put("identitiesAlias", nickname);
                    dbUtils.insertIdentity(map);

                    map.clear();
                    map.put("certsName", dsp12filename);
                    map.put("certsPath", "Documents/otoh.io/" + nickname);
                    map.put("certsKeyUse", "Digital Signature");
                    map.put("certsFingerprint", dsFingerprint);
                    dbUtils.insertCert(map, username);

                    map.clear();
                    map.put("certsName", kep12filename);
                    map.put("certsPath", "Documents/otoh.io/" + nickname);
                    map.put("certsKeyUse", "Key Encipherment");
                    map.put("certsFingerprint", keFingerprint);
                    dbUtils.insertCert(map, username);

                    map.clear();
                    map.put("keyringsName", skrname);
                    map.put("keyringsPath", "Documents/otoh.io/" + nickname);
                    map.put("keyringsType", "Secret Keyring");
                    map.put("keyringsFingerprint", "not implemented");
                    dbUtils.insertCert(map, username);

                    map.clear();
                    map.put("keyringsName", pkrname);
                    map.put("keyringsPath", "Documents/otoh.io/" + nickname);
                    map.put("keyringsType", "Public Keyring");
                    map.put("keyringsFingerprint", fingerprint);
                    dbUtils.insertCert(map, username);

                    // All done!
                    updateProgress("Complete");
                    SystemClock.sleep(1000);

                    // Set first run to false
                    Context context = getApplicationContext();
                    SharedPreferences sharedPreferences = context.getSharedPreferences(
                            getString(R.string.preference_file_key), Context.MODE_PRIVATE);
                    SharedPreferences.Editor editor = sharedPreferences.edit();
                    editor.putString("app_first_run", "false");
                    editor.commit();

                    return "success";

                } catch (Exception e) {
                    Log.e("+++++debug", "exception caught");
                    e.printStackTrace();
                }
                return "failed";
            }

            @Override protected void onPostExecute(String result) {
                pd.dismiss();
                Intent intent = new Intent(GenIdentityActivity.this, DisplayCertsActivity.class);
                intent.putExtra("fingerprint", fingerprint);
                intent.putExtra("dsCert", dsCert);
                intent.putExtra("keCert", keCert);
                intent.putExtra("nickname", nickname);
                startActivity(intent);
            }
        }.executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, nickname);


    } // end onCreate

    // taken from stackoverflow
    public void copy(File src, File dst) throws IOException {
        InputStream in = new FileInputStream(src);
        OutputStream out = new FileOutputStream(dst);

        // Transfer bytes from in to out
        byte[] buf = new byte[1024];
        int len;
        while ((len = in.read(buf)) > 0) {
            out.write(buf, 0, len);
        }
        in.close();
        out.close();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.gen_identity, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
}
