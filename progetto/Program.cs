// Uso:  dotnet run server | dotnet run client
string modo = args.Length > 0 ? args[0] : "";

if (modo == "server")
{
    Server.Start(5000, "readings.json");
    Console.WriteLine("Server in ascolto su http://localhost:5000/  (Ctrl+C per fermare)");
    await Task.Delay(Timeout.Infinite);
}
else if (modo == "client") await Client.Run("http://localhost:5000");
else Console.WriteLine("Uso: dotnet run server | client");
