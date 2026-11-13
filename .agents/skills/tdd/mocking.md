# When to fake

Fake at **system boundaries** only (`.claude/skills/codebase-design`, DEEPENING.md's categories 3
and 4):

- the network and other processes (the master server, a dedicated server): a socket on localhost or
  an in-memory adapter;
- time and randomness: a clock and a seed passed in;
- the file system, sometimes: a temporary folder is usually the better stand-in;
- the OS, the GPU and the guest, behind the port the module already takes them through.

Don't fake:

- your own modules and classes;
- internal collaborators;
- anything you control.

## Designing for fakes

At a system boundary, design the interface so a fake is easy:

**1. Pass the dependency in** rather than creating it inside.

```cpp
// Easy to fake: the master's client is passed in.
Result<Session> SignIn(MasterClient& master, const PlayerKey& key);

// Hard to fake: it opens its own connection from the environment.
Result<Session> SignIn(const PlayerKey& key);  // reads GM_MASTER_URL, opens a socket
```

**2. One function per operation** rather than one generic request with conditions inside.

```cpp
// GOOD: each operation is faked on its own and returns one shape.
struct MasterClient {
  virtual Result<Session> SignIn(const PlayerKey&) = 0;
  virtual Result<ServerList> Servers(const Filter&) = 0;
};

// BAD: a fake needs conditional logic to answer each path.
struct MasterClient {
  virtual Result<Json> Request(std::string_view path, const Json& body) = 0;
};
```

Then each fake returns one specific shape, a test's setup has no conditions, and it is plain which
operations a test exercises.
