using System.Text;
using System.Text.Json.Nodes;

// Un sensore: fa l'handshake, poi invia messaggi cifrati
class Sensor
{
    HttpClient http = new();
    string url;
    public string Id, Merce;
    public string Sid;
    public byte[] Key;

    public Sensor(string url, string id, string merce) { this.url = url; Id = id; Merce = merce; }

    public async Task Handshake()
    {
        var a = Crypto.NewSecret();                          // segreto del client
        var req = new JsonObject
        {
            ["p"] = Crypto.Hex(Crypto.P),
            ["g"] = "2",
            ["client_public"] = Crypto.Hex(Crypto.Public(a))   // A = g^a mod p
        };
        var (stato, testo) = await Post("/api/handshake", req.ToJsonString());
        if (stato != 200) throw new Exception("Handshake fallito: " + testo);

        var r = JsonNode.Parse(testo);
        string err = Validator.Check("handshake-response", r);
        if (err != null) throw new Exception("Risposta handshake non valida: " + err);

        Sid = (string)r["session_id"];
        Key = Crypto.MakeKey(Crypto.FromHex((string)r["server_public"]), a);   // K = B^a mod p
    }

    // valida con lo schema -> cifra -> invia -> decifra la risposta
    public async Task<(int, JsonNode)> Send(string path, string schemaRichiesta, string schemaRisposta,
                                            JsonObject msg, bool valida = true)
    {
        if (valida)
        {
            string err = Validator.Check(schemaRichiesta, msg);
            if (err != null) throw new Exception("Messaggio non valido, non inviato: " + err);
        }
        var busta = Crypto.Encrypt(Sid, Key, msg.ToJsonString());
        var (stato, testo) = await Post(path, busta.ToJsonString());

        var risposta = JsonNode.Parse(testo);
        if (risposta["ciphertext"] != null) risposta = JsonNode.Parse(Crypto.Decrypt(Key, risposta));

        string errRisp = Validator.Check(stato == 200 ? schemaRisposta : "error", risposta);
        if (errRisp != null) throw new Exception("Risposta non valida: " + errRisp);
        return (stato, risposta);
    }

    public Task<(int, JsonNode)> SendMeasure(JsonObject m, bool valida = true) =>
        Send("/api/telemetry", "telemetry", "ack", m, valida);

    public Task<(int, JsonNode)> GetReadings() =>
        Send("/api/readings", "readings-request", "readings-response", new JsonObject { ["sensor_id"] = Id });

    public Task<(int, JsonNode)> Close() =>
        Send("/api/close", "close-request", "ack", new JsonObject { ["action"] = "close" });

    public async Task<(int, string)> Post(string path, string json)
    {
        var res = await http.PostAsync(url + path, new StringContent(json, Encoding.UTF8, "application/json"));
        return ((int)res.StatusCode, await res.Content.ReadAsStringAsync());
    }

    // misura simulata: ogni tanto la temperatura sale e scatta l'allarme
    public JsonObject NewMeasure()
    {
        double baseT = Merce == "pharma" ? 5 : Merce == "food" ? 2 : -21;
        double t = baseT + Random.Shared.NextDouble() * 3 - 1.5;
        if (Random.Shared.Next(5) == 0) t += 8;

        return new JsonObject
        {
            ["sensor_id"] = Id,
            ["timestamp"] = DateTime.UtcNow.ToString("s") + "Z",
            ["cargo_type"] = Merce,
            ["temperature_c"] = Math.Round(t, 1),
            ["humidity"] = Random.Shared.Next(40, 70),
            ["battery"] = Random.Shared.Next(20, 100)
        };
    }
}

static class Client
{
    public static async Task Run(string url)
    {
        var sensori = new[]
        {
            new Sensor(url, "CELLA-BG-007", "pharma"),
            new Sensor(url, "CAMION-MI-012", "food"),
            new Sensor(url, "CELLA-TO-003", "frozen")
        };
        // i 3 sensori lavorano in parallelo; solo il primo manda anche una misura sbagliata (demo)
        await Task.WhenAll(sensori.Select((s, i) => Vita(s, i == 0)));
    }

    static async Task Vita(Sensor s, bool demoNonValida)
    {
        await s.Handshake();                                 // prima l'handshake
        Console.WriteLine($"{s.Id}: handshake ok, sessione {s.Sid}");

        for (int i = 0; i < 5; i++)                          // 5 misure a intervalli regolari
        {
            var m = s.NewMeasure();
            var (stato, r) = await s.SendMeasure(m);
            Console.WriteLine($"{s.Id}: {m["temperature_c"]} C -> {stato}, allarme: {r["alarm"]}");
            await Task.Delay(2000);
        }

        if (demoNonValida)
        {
            var sbagliata = s.NewMeasure();
            sbagliata["temperature_c"] = 99;
            var (stato, r) = await s.SendMeasure(sbagliata, valida: false);   // salto il controllo locale
            Console.WriteLine($"{s.Id}: misura NON valida -> {stato}: {r["message"]}");
        }

        var (_, letture) = await s.GetReadings();
        Console.WriteLine($"{s.Id}: il server ha {letture["count"]} misure");

        var (_, chiusura) = await s.Close();
        Console.WriteLine($"{s.Id}: sessione {chiusura["status"]}");
    }
}
