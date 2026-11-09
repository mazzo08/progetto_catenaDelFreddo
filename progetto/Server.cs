using System.Collections.Concurrent;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

static class Server
{
    static HttpListener listener = new HttpListener();
    static ConcurrentDictionary<string, byte[]> sessioni = new ConcurrentDictionary<string, byte[]>();  // session_id -> chiave
    static JsonArray misure = new JsonArray();
    static object blocco = new object();
    static string fileMisure = "readings.json";

    public static void Start(int porta, string file)
    {
        fileMisure = file;
        if (File.Exists(file))
            misure = JsonNode.Parse(File.ReadAllText(file)).AsArray();

        listener.Prefixes.Add("http://localhost:" + porta + "/");
        listener.Start();
        Task.Run(Ascolta);
    }

    // aspetta le richieste; ognuna viene gestita in un task diverso (piu' client insieme)
    static async Task Ascolta()
    {
        while (true)
        {
            HttpListenerContext ctx = await listener.GetContextAsync();
            Task.Run(() => Gestisci(ctx));
        }
    }

    // guarda quale endpoint e' stato chiamato e lancia la funzione giusta
    static void Gestisci(HttpListenerContext ctx)
    {
        try
        {
            string body = new StreamReader(ctx.Request.InputStream).ReadToEnd();
            string rotta = ctx.Request.HttpMethod + " " + ctx.Request.Url.AbsolutePath;

            if (rotta == "POST /api/handshake") Handshake(ctx, body);
            else if (rotta == "POST /api/telemetry") Telemetria(ctx, body);
            else if (rotta == "POST /api/readings") Letture(ctx, body);
            else if (rotta == "POST /api/close") Chiudi(ctx, body);
            else Errore(ctx, 404, "Endpoint inesistente");
        }
        catch (Exception e)
        {
            Errore(ctx, 500, e.Message);
        }
    }

    // ================= ENDPOINT =================

    // /api/handshake: l'unico messaggio in chiaro
    static void Handshake(HttpListenerContext ctx, string body)
    {
        JsonNode req = Leggi(body);

        string err = Validator.Check("handshake-request", req);
        if (err != null) { Errore(ctx, 400, err); return; }

        BigInteger p = Crypto.FromHex((string)req["p"]);
        BigInteger g = Crypto.FromHex((string)req["g"]);
        BigInteger A = Crypto.FromHex((string)req["client_public"]);

        if (p != Crypto.P || g != Crypto.G) { Errore(ctx, 400, "Gruppo Diffie-Hellman non valido"); return; }
        if (A <= 1 || A >= Crypto.P - 1) { Errore(ctx, 400, "Chiave pubblica non valida"); return; }

        BigInteger b = Crypto.NewSecret();   // segreto del server
        BigInteger B = Crypto.Public(b);     // B = g^b mod p
        byte[] chiave = Crypto.MakeKey(A, b);                // K = A^b mod p

        string sid = Convert.ToHexString(RandomNumberGenerator.GetBytes(4)).ToLower();
        sessioni[sid] = chiave;

        JsonObject risposta = new JsonObject();
        risposta["session_id"] = sid;
        risposta["server_public"] = Crypto.Hex(B);
        Invia(ctx, 200, risposta.ToJsonString());
    }

    // /api/telemetry: riceve una misura
    static void Telemetria(HttpListenerContext ctx, string body)
    {
        JsonNode busta = Leggi(body);
        JsonNode m = Apri(ctx, busta, "telemetry");
        if (m == null) return;       // Apri ha gia' risposto con l'errore

        double temp = (double)m["temperature_c"];
        string merce = (string)m["cargo_type"];

        // intervallo di sicurezza
        double min = 0, max = 4;                                // food
        if (merce == "pharma") { min = 2; max = 8; }
        if (merce == "frozen") { min = -25; max = -18; }

        lock (blocco)
        {
            misure.Add(m);
            File.WriteAllText(fileMisure, misure.ToJsonString());
        }

        JsonObject risposta = new JsonObject();
        risposta["status"] = "ok";
        risposta["alarm"] = temp < min || temp > max;
        InviaCifrato(ctx, 200, busta, risposta);
    }

    // /api/readings: restituisce le misure di un sensore
    static void Letture(HttpListenerContext ctx, string body)
    {
        JsonNode busta = Leggi(body);
        JsonNode m = Apri(ctx, busta, "readings-request");
        if (m == null) return;

        string sensore = (string)m["sensor_id"];
        DateTime da = DateTime.MinValue;
        DateTime a = DateTime.MaxValue;
        if (m["from"] != null) da = DateTime.Parse((string)m["from"]);
        if (m["to"] != null) a = DateTime.Parse((string)m["to"]);

        JsonArray elenco = new JsonArray();
        lock (blocco)
        {
            foreach (JsonNode r in misure)
            {
                DateTime quando = DateTime.Parse((string)r["timestamp"]);
                if ((string)r["sensor_id"] == sensore && quando >= da && quando <= a)
                    elenco.Add(r.DeepClone());
            }
        }

        JsonObject risposta = new JsonObject();
        risposta["sensor_id"] = sensore;
        risposta["count"] = elenco.Count;
        risposta["readings"] = elenco;
        InviaCifrato(ctx, 200, busta, risposta);
    }

    // /api/close: chiude la sessione e cancella la chiave
    static void Chiudi(HttpListenerContext ctx, string body)
    {
        JsonNode busta = Leggi(body);
        JsonNode m = Apri(ctx, busta, "close-request");
        if (m == null) return;

        JsonObject risposta = new JsonObject();
        risposta["status"] = "closed";
        InviaCifrato(ctx, 200, busta, risposta);

        sessioni.TryRemove((string)busta["session_id"], out byte[] vecchiaChiave);   // cancella la sessione
    }

    // ================= FUNZIONI DI SUPPORTO =================

    // Apre una busta cifrata. Ordine (come richiede il PDF):
    //   1) la busta ha la forma giusta?  2) la sessione esiste?
    //   3) DECIFRA                       4) il contenuto rispetta lo schema?
    // Se qualcosa non va risponde con l'errore e restituisce null.
    // Se va tutto bene restituisce il messaggio decifrato.
    static JsonNode Apri(HttpListenerContext ctx, JsonNode busta, string schema)
    {
        string err = Validator.Check("envelope", busta);
        if (err != null) { Errore(ctx, 400, err); return null; }

        string sid = (string)busta["session_id"];
        if (!sessioni.ContainsKey(sid)) { Errore(ctx, 401, "Sessione inesistente"); return null; }

        JsonNode msg;
        try
        {
            string testo = Crypto.Decrypt(sessioni[sid], busta);
            msg = Leggi(testo);
        }
        catch
        {
            Errore(ctx, 400, "Busta non valida o manomessa");
            return null;
        }

        err = Validator.Check(schema, msg);
        if (err != null) { InviaCifrato(ctx, 400, busta, CreaErrore(400, err)); return null; }

        return msg;
    }

    // Trasforma il testo in JSON; se non e' un JSON valido restituisce null
    static JsonNode Leggi(string testo)
    {
        try { return JsonNode.Parse(testo); }
        catch { return null; }
    }

    static JsonObject CreaErrore(int codice, string testo)
    {
        JsonObject e = new JsonObject();
        e["status"] = codice;
        e["message"] = testo;
        return e;
    }

    // errore in chiaro (usato quando non c'e' ancora una chiave)
    static void Errore(HttpListenerContext ctx, int codice, string testo)
    {
        Invia(ctx, codice, CreaErrore(codice, testo).ToJsonString());
    }

    // risposta cifrata con la chiave della sessione
    static void InviaCifrato(HttpListenerContext ctx, int codice, JsonNode busta, JsonObject risposta)
    {
        string sid = (string)busta["session_id"];
        JsonObject cifrata = Crypto.Encrypt(sid, sessioni[sid], risposta.ToJsonString());
        Invia(ctx, codice, cifrata.ToJsonString());
    }

    // scrive la risposta HTTP
    static void Invia(HttpListenerContext ctx, int codice, string testo)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(testo);
        ctx.Response.StatusCode = codice;
        ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
        ctx.Response.Close();
    }
}
