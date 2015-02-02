package io.otoh.otohio;

import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

import java.util.ArrayList;
import java.util.HashMap;

public class DBUtils extends SQLiteOpenHelper {

    public DBUtils(Context context) {
        super(context, "otohdotio.db", null, 1);

    }

    @Override
    public void onCreate(SQLiteDatabase db) {
        db.execSQL("PRAGMA foreign_keys=ON");

        String query = "CREATE TABLE IF NOT EXIST identities (name TEXT PRIMARY KEY, alias TEXT)";
        db.execSQL(query);
        query = "CREATE TABLE IF NOT EXIST certs (name TEXT PRIMARY KEY, identityName TEXT, path TEXT, keyUse TEXT, finerprint TEXT, FOREIGN KEY (identityName) REFERENCES identities (name)) ON DELETE CASCADE";
        db.execSQL(query);
        query = "CREATE TABLE IF NOT EXIST keyrings (name TEXT PRIMARY KEY, identityName TEXT, path TEXT, type TEXT, fingerprint TEXT, FOREIGN KEY (identityName) REFERENCES identities (name)) ON DELETE CASCADE";
        db.execSQL(query);

    }

    @Override
    public void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion) {
        String query = "DROP TABLE IF EXISTS identities";
        db.execSQL(query);
        query = "DROP TABLE IF EXISTS certs";
        db.execSQL(query);
        query = "DROP TABLE IF EXISTS keyrings";
        db.execSQL(query);

        onCreate(db);
    }

    // TODO: write database dump and restore logic

    @Override
    public void onOpen(SQLiteDatabase db) {
        super.onOpen(db);
        if (!db.isReadOnly()) {
            db.execSQL("PRAGMA foreign_keys=ON;");
        }
    }

    public void insertIdentity(HashMap<String, String> queryValues) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues valuesIdentity = new ContentValues();

        valuesIdentity.put("name", queryValues.get("identitiesName"));
        valuesIdentity.put("alias", queryValues.get("identitiesAlias"));

        db.insert("identities", null, valuesIdentity);
        db.close();
    }

    public void insertCert(HashMap<String, String> queryValues, String identity) {
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues valuesCerts = new ContentValues();

        valuesCerts.put("name", queryValues.get("certsName"));
        valuesCerts.put("identityName", identity);
        valuesCerts.put("path", queryValues.get("certsPath"));
        valuesCerts.put("keyUse", queryValues.get("certsKeyUse"));
        valuesCerts.put("fingerprint", queryValues.get("certsFingerprint"));

        db.insert("certs", null, valuesCerts);
        db.close();
    }

    public void insertKeyring(HashMap<String, String> queryValues, String identity){
        SQLiteDatabase db = this.getWritableDatabase();
        ContentValues valuesKeyrings = new ContentValues();

        valuesKeyrings.put("name", queryValues.get("keyringsName"));
        valuesKeyrings.put("identityName", identity);
        valuesKeyrings.put("path", queryValues.get("keyringsPath"));
        valuesKeyrings.put("type", queryValues.get("keyringsType"));
        valuesKeyrings.put("fingerprint", queryValues.get("keyringsFingerprint"));

        db.insert("keyrings", null, valuesKeyrings);
        db.close();
    }

    // TODO: addCert()

    // TODO: addKeyring()

    // TODO: deleteCert();

    // TODO: deleteKeyring();

    public void deleteIdentity(String name){
        SQLiteDatabase db = this.getWritableDatabase();
        String query = "DELETE FROM identities WHERE name = '" + name + "'";
        db.execSQL(query);
        db.close();
    }

    public ArrayList<HashMap<String, String>> getIdentities(){
        ArrayList<HashMap<String, String>> list = new ArrayList<HashMap<String, String>>();
        String query = "SELECT * FROM identities";
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery(query, null);
        if(cursor.moveToFirst()) {
            do {
                HashMap<String, String> map = new HashMap<String, String>();
                map.put("name", cursor.getString(0));
                map.put("alias", cursor.getString(1));
                list.add(map);
            } while(cursor.moveToNext());
        }
        return list;
    }

    public ArrayList<HashMap<String, String>> getCerts(String identity){
        ArrayList<HashMap<String, String>> list = new ArrayList<HashMap<String, String>>();
        String query = "SELECT * FROM certs WHERE identityName = '" + identity + "'";
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery(query, null);
        if(cursor.moveToFirst()) {
            do {
                HashMap<String, String> map = new HashMap<String, String>();
                map.put("identityName", cursor.getString(1));
                map.put("name", cursor.getString(2));
                map.put("path", cursor.getString(3));
                map.put("keyUse", cursor.getString(4));
                map.put("fingerprint", cursor.getString(5));
                list.add(map);
            } while(cursor.moveToNext());
        }
        return list;
    }

    public ArrayList<HashMap<String, String>> getKeyrings(String identity){
        ArrayList<HashMap<String, String>> list = new ArrayList<HashMap<String, String>>();
        String query = "SELECT * FROM keyrings WHERE identityName = '" + identity + "'";
        SQLiteDatabase db = this.getWritableDatabase();
        Cursor cursor = db.rawQuery(query, null);
        if(cursor.moveToFirst()) {
            do {
                HashMap<String, String> map = new HashMap<String, String>();
                map.put("identityName", cursor.getString(1));
                map.put("name", cursor.getString(2));
                map.put("path", cursor.getString(3));
                map.put("type", cursor.getString(4));
                map.put("fingerprint", cursor.getString(4));
                list.add(map);
            } while(cursor.moveToNext());
        }
        return list;
    }

}
