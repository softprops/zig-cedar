# zig cedar

\-softprops 2024

<h1 align="center">
    🌲 zig cedar
</h1>

<div align="center">
    Zig bindings for the <a href="https://www.cedarpolicy.com/">Cedar</a> authorization policies
</div>

---

[![Main](https://github.com/softprops/zig-cedar/actions/workflows/ci.yml/badge.svg)](https://github.com/softprops/zig-cedar/actions/workflows/ci.yml) ![License Info](https://img.shields.io/github/license/softprops/zig-cedar) ![Release](https://img.shields.io/github/v/release/softprops/zig-cedar) [![Zig Support](https://img.shields.io/badge/zig-0.13.0-black?logo=zig)](https://ziglang.org/documentation/0.13.0/)

## examples

See examples directory

## 📼 installing

Create a new exec project with `zig init`. Copy an example from the examples directory into your into `src/main.zig`

Create a `build.zig.zon` file to declare a dependency

> .zon short for "zig object notation" files are essentially zig structs. `build.zig.zon` is zigs native package manager convention for where to declare dependencies

Starting in zig 0.12.0, you can use and should prefer

```sh
zig fetch --save https://github.com/softprops/zig-cedar/archive/refs/tags/v0.1.3.tar.gz
```

otherwise, to manually add it, do so as follows

```diff
.{
    .name = "my-app",
    .version = "0.1.0",
    .dependencies = .{
+       // 👇 declare dep properties
+        .cedar = .{
+            // 👇 uri to download
+            .url = "https://github.com/softprops/zig-cedar/archive/refs/tags/v0.1.3.tar.gz",
+            // 👇 hash verification
+            .hash = "...",
+        },
    },
}
```

> the hash below may vary. you can also depend any tag with `https://github.com/softprops/zig-cedar/archive/refs/tags/v{version}.tar.gz` or current main with `https://github.com/softprops/zig-cedar/archive/refs/heads/main/main.tar.gz`. to resolve a hash omit it and let zig tell you the expected value.

Add the following in your `build.zig` file

```diff
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});
    // 👇 de-reference dep from build.zig.zon
+    const cedar = b.dependency("cedar", .{
+        .target = target,
+        .optimize = optimize,
+    }).module("cedar");
    var exe = b.addExecutable(.{
        .name = "your-exe",
        .root_source_file = .{ .path = "src/main.zig" },
        .target = target,
        .optimize = optimize,
    });
    // 👇 add the module to executable
+    exe.root_mode.addImport("cedar", cedar);

    b.installArtifact(exe);
}
```

## 🥹 for budding ziglings

Does this look interesting but you're new to zig and feel left out? No problem, zig is young so most us of our new are as well. Here are some resources to help get you up to speed on zig

- [the official zig website](https://ziglang.org/)
- [zig's one-page language documentation](https://ziglang.org/documentation/0.13.0/)
- [ziglearn](https://ziglearn.org/)
- [ziglings exercises](https://codeberg.org/ziglings/exercises/)

\- softprops 2024
