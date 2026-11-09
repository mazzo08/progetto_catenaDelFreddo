using System.Text.Json.Nodes;
using Json.Schema;

// Valida un messaggio con uno schema della cartella schemas/
static class Validator
{
    // Restituisce null se il messaggio e' valido, altrimenti "campo: errore"
    public static string Check(string nomeSchema, JsonNode messaggio)
    {
        string file = Path.Combine(AppContext.BaseDirectory, "schemas", nomeSchema + ".schema.json");
        var schema = JsonSchema.FromText(File.ReadAllText(file));

        var opzioni = new EvaluationOptions
        {
            OutputFormat = OutputFormat.List,
            RequireFormatValidation = true      // senza, "format" viene ignorato
        };
        var risultato = schema.Evaluate(messaggio, opzioni);
        if (risultato.IsValid) return null;

        foreach (var d in risultato.Details)
            if (!d.IsValid && d.Errors != null && d.Errors.Count > 0)
                return $"{d.InstanceLocation}: {d.Errors.First().Value}";

        return "messaggio non valido";
    }
}
