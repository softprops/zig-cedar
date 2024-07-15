const std = @import("std");

/// https://docs.cedarpolicy.com/policies/syntax-datatypes.html
pub const CedarType = union(enum) {
    pub const Attribute = struct { []const u8, CedarType };
    pub const Record = struct {
        attributes: []const Attribute,
        fn get(self: *const @This(), name: []const u8) ?CedarType {
            for (self.attributes) |attr| {
                if (std.mem.eql(u8, name, attr.@"0")) {
                    return attr.@"1";
                }
            }
            return null;
        }
    };
    /// Extensions are Cedar's way of extending it's typesystem. All Extensions have a name and a means
    /// of parsing their typed value from a string
    pub fn Extension(comptime T: type, comptime name: []const u8, parseFn: fn ([]const u8) anyerror!T) type {
        return struct {
            name: []const u8,
            value: T,
            fn init(value: T) @This() {
                return .{ .name = name, .value = value };
            }
            fn parse(s: []const u8) !@This() {
                return init(try parseFn(s));
            }
        };
    }

    /// A value with both a whole number part and a decimal part of no more than four digits.
    /// https://docs.cedarpolicy.com/policies/syntax-datatypes.html#datatype-decimal
    const Decimal = Extension(f64, "decimal", struct {
        fn parse(s: []const u8) !f64 {
            return try std.fmt.parseFloat(f64, s);
        }
    }.parse);

    /// A value that represents an IP address. It can be either IPv4 or IPv6.
    /// note: only handles ip addresses and not ranges which differs from
    /// https://docs.cedarpolicy.com/policies/syntax-datatypes.html#datatype-ipaddr
    const Ipaddr = Extension(std.net.Address, "ipaddr", struct {
        fn parse(s: []const u8) !std.net.Address {
            return try std.net.Address.parseIp(s, 0);
        }
    }.parse);

    boolean: bool,
    string: []const u8,
    long: u64,
    set: []const CedarType,
    record: Record,
    entity: EntityUID,
    extension: union(enum) {
        ipaddr: Ipaddr,
        decimal: Decimal,
        // register new extensions here
        /// an unknown extension
        unknown: void,
    },

    pub fn ip(value: std.net.Address) @This() {
        return .{ .extension = .{ .ipaddr = Ipaddr.init(value) } };
    }

    pub fn decimal(value: f64) @This() {
        return .{ .extension = .{ .decimal = Decimal.init(value) } };
    }

    pub fn unknownExt() @This() {
        return .{ .extension = .{ .unknown = {} } };
    }

    pub fn boolean(value: bool) @This() {
        return .{ .boolean = value };
    }

    pub fn string(value: []const u8) @This() {
        return .{ .string = value };
    }

    pub fn long(value: u64) @This() {
        return .{ .long = value };
    }

    pub fn record(attributes: []const Attribute) @This() {
        return .{ .record = .{ .attributes = attributes } };
    }

    pub fn set(elems: []const CedarType) @This() {
        return .{ .set = elems };
    }

    pub fn format(
        self: @This(),
        comptime fmt: []const u8,
        opts: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .boolean => |v| try writer.print("{s}", .{v}),
            .string => |v| try writer.print("\"{s}\"", .{v}),
            .long => |v| try writer.print("{s}", .{v}),
            .set => |v| {
                try writer.print("[", .{});
                for (v, 0..) |elem, i| {
                    try writer.print("{s}", .{elem});
                    if (i != v.len - 1) try writer.print(",", .{});
                }
                try writer.print("]", .{});
            },
            .record => |v| {
                try writer.print("{", .{});
                for (v, 0..) |elem, i| {
                    try writer.print("\"{s}\":", .{elem.@"0"});
                    elem.@"0".format(fmt, opts, writer);
                    if (i != v.len - 1) try writer.print(",", .{});
                }
                try writer.print("}", .{});
            },
            .entity => |v| try writer.print("{s}", .{v}),
            .extension => |v| switch (v) {
                .ipaddr => |e| try writer.print("{s}(any)", .{ e.name, e.value }),
                .decimal => |e| try writer.print("{s}({any})", .{ e.name, e.value }),
                .unknown => try writer.print("<unknown>", .{}),
            },
        }
    }

    fn fromJsonValue(allocator: std.mem.Allocator, value: std.json.Value) !@This() {
        return switch (value) {
            .bool => |v| CedarType.boolean(v),
            .integer => |v| CedarType.long(@intCast(v)),
            .float => |v| CedarType.decimal(v),
            .string => |v| CedarType.string(v),
            .array => |v| blk: {
                var elems = std.ArrayList(CedarType).init(allocator);
                defer elems.deinit();
                for (v.items) |elem| {
                    try elems.append(try fromJsonValue(allocator, elem));
                }
                break :blk CedarType.set(try elems.toOwnedSlice());
            },
            .object => |v| blk: {
                var attrs = std.ArrayList(CedarType.Attribute).init(allocator);
                defer attrs.deinit();
                var it = v.iterator();
                while (it.next()) |entry| {
                    try attrs.append(.{ entry.key_ptr.*, try fromJsonValue(allocator, entry.value_ptr.*) });
                }
                break :blk CedarType.record(try attrs.toOwnedSlice());
            },
            else => @panic("unsupported json type " ++ @typeName(@TypeOf(value))),
        };
    }
};

test CedarType {
    // record + attr access
    try std.testing.expectEqualStrings(
        CedarType.record(&.{
            .{ "name", CedarType.string("alice") },
        }).record.get("name").?.string,
        "alice",
    );
    try std.testing.expect(
        CedarType.record(&.{}).record.get("name") == null,
    );
    // string
    try std.testing.expectEqualStrings(
        CedarType.string("foo").string,
        "foo",
    );
    // boolean
    try std.testing.expectEqual(CedarType.boolean(true).boolean, true);
    // long
    try std.testing.expectEqual(CedarType.long(1).long, 1);
    // set
    try std.testing.expectEqual(CedarType.set(
        &.{
            CedarType.long(1),
            CedarType.boolean(false),
            CedarType.string("str"),
        },
    ).set.len, 3);
    // decimal ext
    try std.testing.expectEqual(
        CedarType.decimal(1.0).extension.decimal.value,
        @as(f64, 1.0),
    );
    try std.testing.expectEqual(
        (try CedarType.Decimal.parse("1.0")).value,
        @as(f64, 1.0),
    );
    // ipaddr ext
    try std.testing.expectEqual(
        CedarType.ip(try std.net.Address.parseIp("192.168.1.100", 0)).extension.ipaddr.value.in,
        (try std.net.Address.parseIp("192.168.1.100", 0)).in,
    );
    try std.testing.expectEqual(
        (try CedarType.Ipaddr.parse("192.168.1.100")).value.in,
        (try std.net.Address.parseIp("192.168.1.100", 0)).in,
    );
}

/// identifies an entity within the system
pub const EntityUID = struct {
    type: []const u8,
    id: []const u8,
    pub fn init(tp: []const u8, id: []const u8) @This() {
        return .{ .type = tp, .id = id };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}::\"{s}\"", .{ self.type, self.id });
    }
};

pub const Ref = union(enum) {
    id: EntityUID,
    slot: void,

    pub fn slot() @This() {
        return .{ .slot = {} };
    }

    pub fn id(eid: EntityUID) @This() {
        return .{ .id = eid };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .id => |v| try writer.print("{s}", .{v}),
            .slot => try writer.print("<slot>", .{}),
        }
    }
};

/// a scope of access: to whom, for what action and what resource
pub const Scope = struct {
    principal: Principal,
    action: Action,
    resource: Resource,
    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("({s},{s},{s})", .{ self.principal, self.action, self.resource });
    }
};

/// the "who" component of a scope
pub const Principal = union(enum) {
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    //isIn: todo: impl me

    pub fn any() @This() {
        return .{ .any = {} };
    }

    pub fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn eq(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .any => try writer.print("principal", .{}),
            .in => |v| try writer.print("principal in {s}", .{v}),
            .eq => |v| try writer.print("principal == {s}", .{v}),
            .is => |v| try writer.print("principal is {s}", .{v}),
        }
    }
};

/// defines what a principal may or may not do
pub const Action = union(enum) {
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    //isIn: //isIn: todo: impl me

    pub fn any() @This() {
        return .{ .any = {} };
    }

    pub fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn eq(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .any => try writer.print("action", .{}),
            .in => |v| try writer.print("action in {s}", .{v}),
            .eq => |v| try writer.print("action == {s}", .{v}),
            .is => |v| try writer.print("action is {s}", .{v}),
        }
    }
};

/// defines the subject an action is to be taken
pub const Resource = union(enum) {
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    //isIn: //isIn: todo: impl me

    pub fn any() @This() {
        return .{ .any = {} };
    }

    pub fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn eq(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .any => try writer.print("resource", .{}),
            .in => |v| try writer.print("resource in {s}", .{v}),
            .eq => |v| try writer.print("resource == {s}", .{v}),
            .is => |v| try writer.print("resource is {s}", .{v}),
        }
    }
};

pub const Effect = enum { forbid, permit };

pub const Annotation = struct {
    name: []const u8,
    value: []const u8,
    pub fn init(name: []const u8, value: []const u8) @This() {
        return .{ .name = name, .value = value };
    }
    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("@{s}(\"{s}\")", .{ self.name, self.value });
    }
};

// https://github.com/cedar-policy/cedar/blob/b653e6c0627423b24bed50ee664b0302c512f16a/cedar-policy-core/src/ast/expr.rs#L48
pub const Expr = union(enum) {
    pub const Literal = union(enum) {
        bool: bool,
        long: u32,
        string: []const u8,
        entity: EntityUID,
    };
    pub const Var = enum {
        principal,
        action,
        resource,
        context,
    };

    pub const BinaryOp = enum {
        eq,
        lt,
        lte,
        add,
        sub,
        mul,
        in,
        contains,
        contains_all,
        contains_any,
    };
    literal: Literal,
    variable: Var,
    slot: []const u8,
    ite: struct { @"if": *const Expr, then: *const Expr, @"else": *const Expr },
    @"and": struct { left: *const Expr, right: *const Expr },
    @"or": struct { left: *const Expr, right: *const Expr },
    binary: struct { op: BinaryOp, arg1: *const Expr, arg2: *const Expr },

    pub fn literal(value: Literal) @This() {
        return .{ .literal = value };
    }

    pub fn variable(value: Var) @This() {
        return .{ .variable = value };
    }

    pub fn slot(value: []const u8) @This() {
        return .{ .slot = value };
    }

    pub fn @"and"(l: Expr, r: Expr) @This() {
        return .{ .@"and" = .{ .left = l, .right = r } };
    }

    pub fn @"or"(l: Expr, r: Expr) @This() {
        return .{ .@"or" = .{ .left = l, .right = r } };
    }

    /// if .. then .. else ..
    pub fn ite(i: Expr, t: Expr, e: Expr) @This() {
        return .{
            .ite = .{ .@"if" = &i, .then = &t, .@"else" = &e },
        };
    }

    pub fn in(arg1: Expr, arg2: Expr) @This() {
        return .{
            .binary = .{ .op = .in, .arg1 = &arg1, .arg2 = &arg2 },
        };
    }

    pub fn format(
        _: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("<expr>", .{});
    }
};

/// the core building block of permiting or denying access to perform an action against a given resource
pub const Policy = struct {
    annotations: []const Annotation,
    effect: Effect,
    scope: Scope,
    when: ?Expr = null,
    unless: ?Expr = null,

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        for (self.annotations) |a| try writer.print("{s}\n", .{a});
        try writer.print("{s}{s}", .{ @tagName(self.effect), self.scope });
        if (self.when) |w| try writer.print(" when {{ {s} }}", .{w});
        if (self.unless) |u| try writer.print(" unless {{ {s} }}", .{u});
        try writer.print(";", .{});
    }
};

/// a collection of policies defined by a template
pub const PolicySet = struct {
    arena: *std.heap.ArenaAllocator,
    policies: []const Policy,
    pub fn deinit(self: *@This()) void {
        const alloc = self.arena.child_allocator;
        self.arena.deinit();
        alloc.destroy(self.arena);
    }
};

pub const Entity = struct {
    uuid: EntityUID,
    //attrs:  std.StringHashMap(PartialValueSerializedAsExpr),
    ancestors: std.ArrayList(EntityUID),
};

/// https://docs.cedarpolicy.com/auth/entities-syntax.html
pub const Entities = struct {
    pub const Mode = enum { concrete, partial };

    // todo
    //allocator: std.mem.Allocator,
    //entities: std.AutoHashMap(EntityUID, Entity),
    mode: Mode = .concrete,
};

const EntityJson = struct {
    pub const EntityJsonExt = struct {
        @"fn": []const u8,
        arg: []const u8,

        pub fn format(
            self: @This(),
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print("{s}(\"{s}\")", .{ self.@"fn", self.arg });
        }

        fn fromJsonValue(value: std.json.Value) @This() {
            return .{
                .@"fn" = value.object.get("fn").?.string,
                .arg = value.object.get("arg").?.string,
            };
        }
    };

    pub const EntityJsonUID = union(enum) {
        const Explicit = struct {
            __entity: EntityUID,
        };
        /// implicit form of entity uids
        implicit: EntityUID,
        /// explicit form of entity uids
        explicit: Explicit,

        fn normalize(self: @This()) EntityUID {
            return switch (self) {
                .implicit => |v| v,
                .explicit => |v| v.__entity,
            };
        }

        pub fn format(
            self: @This(),
            comptime _: []const u8,
            _: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            try writer.print("{s}", .{self.normalize()});
        }

        // provided to enable json parsing to correct deserialize union members
        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
            return fromJsonValue(try std.json.innerParse(std.json.Value, allocator, source, options));
        }

        fn fromJsonValue(value: std.json.Value) @This() {
            if (value.object.contains("__entity")) {
                const exp = value.object.get("__entity").?.object;
                return .{ .explicit = .{ .__entity = EntityUID.init(exp.get("type").?.string, exp.get("id").?.string) } };
            } else {
                return .{ .implicit = EntityUID.init(value.object.get("type").?.string, value.object.get("id").?.string) };
            }
        }
    };

    const EntityJsonValue = union(enum) {
        cedar: CedarType,
        __extn: EntityJsonExt,
        __entity: EntityJsonUID,

        pub fn format(
            self: @This(),
            comptime fmt: []const u8,
            opts: std.fmt.FormatOptions,
            writer: anytype,
        ) !void {
            switch (self) {
                .cedar => |v| v.format(fmt, opts, writer),
                .__extn => |v| v.format(fmt, opts, writer),
                .__entity => |v| v.format(fmt, opts, writer),
            }
        }

        pub fn jsonParse(allocator: std.mem.Allocator, source: anytype, options: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
            const raw = try std.json.innerParse(std.json.Value, allocator, source, options);
            return switch (raw) {
                .object => |o| blk: {
                    if (o.contains("__extn")) {
                        break :blk .{ .__extn = EntityJsonExt.fromJsonValue(o.get("__extn").?) };
                    }
                    // explicit and implicit ids are supported
                    if (o.contains("__entity") or (o.contains("type") and o.contains("id"))) {
                        break :blk .{ .__entity = EntityJsonUID.fromJsonValue(raw) };
                    }
                    break :blk .{ .cedar = try CedarType.fromJsonValue(allocator, raw) };
                },
                else => .{ .cedar = try CedarType.fromJsonValue(allocator, raw) },
            };
        }
    };

    uid: EntityJsonUID,
    parents: []const EntityJsonUID,
    attrs: std.json.ArrayHashMap(EntityJsonValue),
};

test EntityJson {
    //if (true) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var parsed = try std.json.parseFromSlice([]const EntityJson, allocator,
        \\[
        \\    {
        \\        "uid": { "type": "User", "id": "alice" },
        \\        "attrs": {
        \\            "department": "HardwareEngineering",
        \\            "jobLevel": 5,
        \\            "homeIp": { "__extn": { "fn": "ip", "arg": "222.222.222.7" } },
        \\            "confidenceScore": { "__extn": { "fn": "decimal", "arg": "33.57" } }
        \\        },
        \\        "parents": [
        \\            { "type": "UserGroup", "id": "alice_friends" },
        \\            { "type": "UserGroup", "id": "bob_friends" }
        \\        ]
        \\    },
        \\    {
        \\        "uid": { "type": "User", "id": "ahmad"},
        \\        "attrs" : {
        \\            "department": "HardwareEngineering",
        \\            "jobLevel": 4,
        \\            "manager": { "__entity": { "type": "User", "id": "alice" } }
        \\        },
        \\        "parents": []
        \\    }
        \\]
    , .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    for (parsed.value, 0..) |entity, i| {
        if (i == 0) {
            try std.testing.expectEqualStrings("alice", entity.uid.normalize().id);
            try std.testing.expectEqual(4, entity.attrs.map.count());
            try std.testing.expectEqual(2, entity.parents.len);
        }
        if (i == 1) {
            try std.testing.expectEqualStrings("ahmad", entity.uid.normalize().id);
            try std.testing.expectEqual(3, entity.attrs.map.count());
            try std.testing.expectEqual(0, entity.parents.len);
        }
    }
}

pub const Schema = struct {
    // todo
};

pub const Context = struct {
    // todo
};
