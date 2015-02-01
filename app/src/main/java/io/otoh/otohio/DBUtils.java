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

        String query = "CREATE TABLE identities (name TEXT PRIMARY KEY, alias TEXT)";
        db.execSQL(query);
        query = "CREATE TABLE certs (id INTEGER PRIMARY KEY, identityName TEXT, name TEXT, keyUse TEXT, path TEXT, FOREIGN KEY (identityName) REFERENCES identities (name)) ON DELETE CASCADE";
        db.execSQL(query);
        query = "CREATE TABLE keyrings (id INTEGER PRIMARY KEY, identityName TEXT, name TEXT, type TEXT, fingerprint TEXT, path TEXT, FOREIGN KEY (identityName) REFERENCES identities (name)) ON DELETE CASCADE";
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
        ContentValues valuesCerts = new ContentValues();
        ContentValues valuesKeyrings = new ContentValues();

        valuesIdentity.put("name", queryValues.get("identitiesName"));
        valuesIdentity.put("alias", queryValues.get("identitiesAlias"));

        valuesCerts.put("id", queryValues.get("certsId"));
        valuesCerts.put("name", queryValues.get("certsName"));
        valuesCerts.put("keyUse", queryValues.get("certsKeyUse"));
        valuesCerts.put("path", queryValues.get("certsPath"));

        valuesKeyrings.put("keyringId", queryValues.get("keyringsId"));
        valuesKeyrings.put("name", queryValues.get("keyringsName"));
        valuesKeyrings.put("type", queryValues.get("keyringsType"));
        valuesKeyrings.put("fingerprint", queryValues.get("keyringsFingerprint"));
        valuesKeyrings.put("path", queryValues.get("keyringsPath"));

        db.insert("identities", null, valuesIdentity);
        db.insert("certs", null, valuesCerts);
        db.insert("keyrings", null, valuesKeyrings);

        db.close();

    }

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
                map.put("id", cursor.getString(0));
                map.put("identityName", cursor.getString(1));
                map.put("name", cursor.getString(2));
                map.put("keyUse", cursor.getString(3));
                map.put("path", cursor.getString(4));
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
                map.put("id", cursor.getString(0));
                map.put("identityName", cursor.getString(1));
                map.put("name", cursor.getString(2));
                map.put("type", cursor.getString(3));
                map.put("fingerprint", cursor.getString(4));
                map.put("path", cursor.getString(5));
                list.add(map);
            } while(cursor.moveToNext());
        }
        return list;
    }

}
