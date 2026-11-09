using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;

// Diffie-Hellman (con BigInteger.ModPow) + cifratura AES-GCM
static class Crypto
{
    // Numero primo noto: RFC 3526, 2048 bit. g = 2.
    public static readonly BigInteger P = FromHex(
        "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74" +
        "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437" +
        "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed" +
        "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf05" +
        "98da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb" +
        "9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3b" +
        "e39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf695581718" +
        "3995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff");
    public static readonly BigInteger G = 2;

    public static BigInteger FromHex(string s) => BigInteger.Parse("0" + s, NumberStyles.HexNumber);
    public static string Hex(BigInteger n) => n.ToString("x").TrimStart('0');

    // segreto casuale (a per il client, b per il server): non viaggia mai in rete
    public static BigInteger NewSecret() => new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true);

    // A = g^a mod p   (il server fa B = g^b mod p)
    public static BigInteger Public(BigInteger segreto) => BigInteger.ModPow(G, segreto, P);

    // K = B^a mod p (client) = A^b mod p (server). La chiave AES e' lo SHA-256 di K.
    public static byte[] MakeKey(BigInteger altraChiavePubblica, BigInteger segreto)
    {
        BigInteger k = BigInteger.ModPow(altraChiavePubblica, segreto, P);
        return SHA256.HashData(k.ToByteArray());
    }

    // Crea la busta {session_id, ciphertext, tag}. Il nonce (12 byte) sta davanti al ciphertext.
    public static JsonObject Encrypt(string sid, byte[] key, string json)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plain = Encoding.UTF8.GetBytes(json);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plain, cipher, tag, Encoding.UTF8.GetBytes(sid));
        return new JsonObject
        {
            ["session_id"] = sid,
            ["ciphertext"] = Convert.ToBase64String(nonce.Concat(cipher).ToArray()),
            ["tag"] = Convert.ToBase64String(tag)
        };
    }

    // Lancia un'eccezione se la busta e' stata manomessa (il tag non torna)
    public static string Decrypt(byte[] key, JsonNode busta)
    {
        byte[] data = Convert.FromBase64String((string)busta["ciphertext"]);
        byte[] tag = Convert.FromBase64String((string)busta["tag"]);
        byte[] cipher = data[12..];
        byte[] plain = new byte[cipher.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(data[..12], cipher, tag, plain, Encoding.UTF8.GetBytes((string)busta["session_id"]));
        return Encoding.UTF8.GetString(plain);
    }
}
