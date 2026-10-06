namespace Yura.Agent.Tests;

/// <summary>
/// The agent's key, token and name on disk, and who may write them.
/// </summary>
/// <remarks>
/// <c>install</c> and <c>show</c> run as root against the service's own state directory. A file
/// they rewrote there belonged to root from then on, and the service, which runs as the
/// directory's owner, failed at every start after its next restart. So reading must not write.
/// </remarks>
public sealed class AgentIdentityTests : IDisposable
{
    private static readonly DateTime LongAgo = new(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    private readonly string _directory = Path.Combine(Path.GetTempPath(), $"yura-identity-{Guid.NewGuid():N}");

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    /// <summary>Marks every file as written long ago, so any write since shows.</summary>
    private void Age()
    {
        foreach (var file in Directory.EnumerateFiles(_directory))
        {
            File.SetLastWriteTimeUtc(file, LongAgo);
        }
    }

    private string[] Rewritten() =>
        Directory.EnumerateFiles(_directory)
            .Where(f => File.GetLastWriteTimeUtc(f) != LongAgo)
            .Select(f => new FileInfo(f).Name)
            .ToArray();

    [Fact]
    public void Loading_writes_nothing()
    {
        var created = AgentIdentity.LoadOrCreate(_directory, "tokyo");
        Age();

        var loaded = AgentIdentity.Load(_directory);

        Assert.NotNull(loaded);
        Assert.Empty(Rewritten());
        Assert.Equal(created.Fingerprint, loaded.Fingerprint);
        Assert.Equal(created.Token, loaded.Token);
        Assert.Equal("tokyo", loaded.Name);
    }

    [Fact]
    public void Loading_an_identity_from_before_names_were_kept_writes_nothing_either()
    {
        AgentIdentity.LoadOrCreate(_directory, "tokyo");
        File.Delete(Path.Combine(_directory, "name"));
        Age();

        var loaded = AgentIdentity.Load(_directory);

        Assert.NotNull(loaded);
        Assert.False(File.Exists(Path.Combine(_directory, "name")));
        Assert.Empty(Rewritten());
    }

    [Fact]
    public void Starting_again_with_the_same_name_leaves_the_files_alone()
    {
        AgentIdentity.LoadOrCreate(_directory, "tokyo");
        Age();

        AgentIdentity.LoadOrCreate(_directory, "tokyo");
        AgentIdentity.LoadOrCreate(_directory);

        Assert.Empty(Rewritten());
    }

    [Fact]
    public void A_new_name_is_written()
    {
        AgentIdentity.LoadOrCreate(_directory, "tokyo");
        Age();

        var renamed = AgentIdentity.LoadOrCreate(_directory, "osaka");

        Assert.Equal("osaka", renamed.Name);
        Assert.Equal("name", Assert.Single(Rewritten()));
        Assert.Equal("osaka", AgentIdentity.Load(_directory)!.Name);
    }

    [Fact]
    public void Nothing_is_loaded_where_the_agent_has_never_run()
    {
        Directory.CreateDirectory(_directory);

        Assert.Null(AgentIdentity.Load(_directory));
        Assert.Empty(Directory.EnumerateFileSystemEntries(_directory));
    }

    [Fact]
    public void Files_written_as_an_ordinary_user_stay_theirs()
    {
        // Handing a file to the directory's owner is for root only; anyone else already is the
        // owner of what they create, and could not give it away if they tried.
        AgentIdentity.LoadOrCreate(_directory, "tokyo");
        var owner = FileOwnership.Of(_directory);

        Assert.NotNull(owner);
        Assert.All(Directory.EnumerateFiles(_directory), f => Assert.Equal(owner, FileOwnership.Of(f)));
        Assert.Equal(0, FileOwnership.Repair(_directory));
    }
}
