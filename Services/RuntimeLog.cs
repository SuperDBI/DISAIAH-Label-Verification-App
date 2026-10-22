using System;
using System.Collections.ObjectModel;

namespace SecRev.Services;

internal sealed class RuntimeLog
{
    public ObservableCollection<string> Entries { get; } = new();

    public void Add(string message)
    {
        Entries.Insert(0, $"{DateTime.Now:HH:mm:ss}  {message}");
        while (Entries.Count > 30)
        {
            Entries.RemoveAt(Entries.Count - 1);
        }
    }
}
