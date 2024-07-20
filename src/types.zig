const std = @import("std");

/// https://docs.cedarpolicy.com/policies/syntax-datatypes.html
pub const CedarType = union(enum) {
    pub const Attribute = struct { []const u8, CedarType };
    pub const Record = struct {
        attributes: []const Attribute,
        fn get(self: *const @This(), name: []const u8) ?CedarType {
            // todo: support indexed lookup
            for (self.attributes) |attr| {
                if (std.mem.eql(u8, name, attr.@"0")) {
                    return attr.@"1";
                }
            }
            return null;
        }
    };
    pub const Set = struct { elems: []const CedarType };

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
    set: Set,
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
        return .{ .set = .{ .elems = elems } };
    }

    /// Aggregate Expr types require pointers to other Exprs.
    /// Use this fn to promote those values onto heap allocated values
    /// callers are responsible for freeing allocated memory
    // pub fn heapify(self: @This(), allocator: std.mem.Allocator) !*const @This() {
    //     const copy = try allocator.create(@This());
    //     copy.* = self;
    //     return copy;
    // }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .boolean => |v| try writer.print("{any}", .{v}),
            .string => |v| try writer.print("\"{s}\"", .{v}),
            .long => |v| try writer.print("{d}", .{v}),
            .set => |v| {
                try writer.print("[", .{});
                for (v.elems, 0..) |elem, i| {
                    try writer.print("{s}", .{elem});
                    if (i != v.elems.len - 1) try writer.print(",", .{});
                }
                try writer.print("]", .{});
            },
            .record => |v| {
                try writer.print("{{", .{});
                for (v.attributes, 0..) |attr, i| {
                    try writer.print("\"{s}\":{s}", .{ attr.@"0", attr.@"1" });
                    //                    attr.@"0".format(fmt, opts, writer);
                    if (i != v.attributes.len - 1) try writer.print(",", .{});
                }
                try writer.print("}}", .{});
            },
            .entity => |v| try writer.print("{s}", .{v}),
            .extension => |v| switch (v) {
                .ipaddr => |e| try writer.print("{s}({any})", .{ e.name, e.value }),
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
    ).set.elems.len, 3);
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

/// Uniquely identifies an namespaced entity within the system
/// of the form `{Type}::"{id}"`
pub const EntityUID = struct {
    type: []const u8,
    id: []const u8,

    pub fn init(tp: []const u8, id: []const u8) @This() {
        return .{ .type = tp, .id = id };
    }

    /// expect str in the form of `{Type}::"{id}"`
    pub fn fromStr(str: []const u8) !@This() {
        if (std.mem.lastIndexOf(u8, str, "::")) |split| {
            return init(str[0..split], str[split + 2 ..]);
        } else {
            return error.MalformedEntityUID;
        }
    }

    pub fn eql(self: @This(), other: EntityUID) bool {
        return std.mem.eql(u8, self.type, other.type) and std.mem.eql(u8, self.id, other.id);
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

test "EntityUID.fromStr" {
    try std.testing.expectEqualDeep(EntityUID.init("Foo", "bar"), try EntityUID.fromStr("Foo::bar"));
}

/// Either a EntityUId or a slot to fill in
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

    /// returs either a literal expr or a slot expr to fill in with a given slot id
    fn toExpr(self: @This(), slotId: SlotId) Expr {
        // todo: fill in slot if possible
        return switch (self) {
            .id => |v| Expr.literal(Expr.Literal.entity(v)),
            .slot => Expr.slot(slotId),
        };
    }
};

test "Ref.toExpr" {
    try std.testing.expectEqualDeep(Expr.slot(.principal), Ref.slot().toExpr(.principal));
    const eid = EntityUID.init("User", "alice");
    try std.testing.expectEqualDeep(Expr.literal(Expr.Literal.entity(eid)), Ref.id(eid).toExpr(.principal));
}

/// A scope of access: to whom, for what action and what resource
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

    fn condition(
        self: @This(),
        allocator: std.mem.Allocator,
    ) !Expr {
        // https://github.com/cedar-policy/cedar/blob/300d50f3798c7962f7d25bcbb01a44f3e30a5304/cedar-policy-core/src/ast/policy.rs#L1015
        // todo: fill principal/resource exprs with slots
        return Expr.@"and"(
            try Expr.@"and"(
                try (try self.principal.toExpr(allocator)).heapify(allocator),
                try (try self.action.toExpr(allocator)).heapify(allocator),
            ).heapify(allocator),
            try (try self.resource.toExpr(allocator)).heapify(allocator),
        );
    }
};

/// The principal element in a Cedar policy represents a role, user, service, or other identity that can make a request to perform an action on a resource in your application. If the principal making the request matches the principal defined in this policy statement, then this element matches.
///
/// The principal element must be present. If you specify only principal without an expression that constrains its scope, then the policy applies to any principal.
///
/// https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-principal
pub const Principal = union(enum) {
    pub const IsIn = struct { is: []const u8, in: Ref };
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    isIn: IsIn,

    pub fn any() @This() {
        return .{ .any = {} };
    }

    pub fn is(value: []const u8) @This() {
        return .{ .is = value };
    }

    pub fn isIn(value: IsIn) @This() {
        return .{ .isIn = value };
    }

    pub fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn eq(ref: Ref) @This() {
        return .{ .eq = ref };
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
            .isIn => |v| try writer.print("principal is {s} in {s}", .{ v.is, v.in }),
        }
    }

    pub fn toExpr(self: *const @This(), allocator: std.mem.Allocator) !Expr {
        return switch (self.*) {
            .any => Expr.literal(Expr.Literal.boolean(true)),
            .in => |v| Expr.in(try Expr.variable(.principal).heapify(allocator), try v.toExpr(.principal).heapify(allocator)),
            .eq => |v| Expr.eq(try Expr.variable(.principal).heapify(allocator), try v.toExpr(.principal).heapify(allocator)),
            .is => |v| Expr.isEntityType(try Expr.variable(.principal).heapify(allocator), v),
            .isIn => |v| Expr.@"and"(
                try Expr.isEntityType(try Expr.variable(.principal).heapify(allocator), v.is).heapify(allocator),
                try Expr.in(try Expr.variable(.principal).heapify(allocator), try v.in.toExpr(.principal).heapify(allocator)).heapify(allocator),
            ),
        };
    }
};

/// The action element in a Cedar policy is a list of the operations in your application for which this policy statement controls access. If the operation in the request matches one of the action items defined in this policy statement, then this element matches.
///
/// https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-action
pub const Action = union(enum) {
    any: void,
    in: []const EntityUID,
    eq: EntityUID,

    pub fn any() @This() {
        return .{ .any = {} };
    }

    pub fn in(list: []const EntityUID) @This() {
        return .{ .in = list };
    }

    pub fn eq(ref: EntityUID) @This() {
        return .{ .eq = ref };
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
        }
    }

    pub fn toExpr(self: *const @This(), allocator: std.mem.Allocator) !Expr {
        return switch (self.*) {
            .any => Expr.literal(Expr.Literal.boolean(true)),
            .in => |v| blk: {
                var set = try std.ArrayList(*const Expr).initCapacity(allocator, v.len);
                for (v) |elem| {
                    set.appendAssumeCapacity(try Expr.literal(Expr.Literal.entity(elem)).heapify(allocator));
                }
                break :blk Expr.in(try Expr.variable(.action).heapify(allocator), try Expr.set(try set.toOwnedSlice()).heapify(allocator));
            },
            .eq => |v| Expr.eq(try Expr.variable(.action).heapify(allocator), try Expr.literal(Expr.Literal.entity(v)).heapify(allocator)), // note: actions will never have slots
        };
    }
};

/// The resource element in a Cedar policy is a resource defined by your application that can be accessed or modified by the specified action.
///
/// resource element must be present. If you specify only resource without an expression that constrains its scope, then the policy applies to any resource.
///
/// https://docs.cedarpolicy.com/policies/syntax-policy.html#term-parc-resource
pub const Resource = union(enum) {
    pub const IsIn = struct { is: []const u8, in: Ref };
    any: void,
    in: Ref,
    eq: Ref,
    is: []const u8,
    isIn: IsIn,

    pub fn any() @This() {
        return .{ .any = {} };
    }

    pub fn in(ref: Ref) @This() {
        return .{ .in = ref };
    }

    pub fn eq(ref: Ref) @This() {
        return .{ .eq = ref };
    }

    pub fn is(value: []const u8) @This() {
        return .{ .is = value };
    }

    pub fn isIn(value: IsIn) @This() {
        return .{ .isIn = value };
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
            .isIn => |v| try writer.print("resource is {s} in {s}", .{ v.is, v.in }),
        }
    }

    pub fn toExpr(self: *const @This(), allocator: std.mem.Allocator) !Expr {
        return switch (self.*) {
            .any => Expr.literal(Expr.Literal.boolean(true)),
            .in => |v| Expr.in(try Expr.variable(.resource).heapify(allocator), try v.toExpr(.resource).heapify(allocator)),
            .eq => |v| Expr.eq(try Expr.variable(.resource).heapify(allocator), try v.toExpr(.resource).heapify(allocator)),
            .is => |v| Expr.isEntityType(try Expr.variable(.resource).heapify(allocator), v),
            .isIn => |v| Expr.@"and"(
                try Expr.isEntityType(try Expr.variable(.resource).heapify(allocator), v.is).heapify(allocator),
                try Expr.in(try Expr.variable(.resource).heapify(allocator), try v.in.toExpr(.resource).heapify(allocator)).heapify(allocator),
            ),
        };
    }
};

pub const Effect = enum { forbid, permit };

/// name of a variable which may be substituted during evaluation
pub const SlotId = enum {
    principal,
    resource,
};

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
/// An Expr is union of types describing of a expression yet to be evaluated
pub const Expr = union(enum) {
    pub const Literal = union(enum) {
        bool: bool,
        long: i64,
        string: []const u8,
        entity: EntityUID,

        pub fn boolean(v: bool) @This() {
            return .{ .bool = v };
        }

        pub fn long(v: i64) @This() {
            return .{ .long = v };
        }

        fn string(v: []const u8) @This() {
            return .{ .string = v };
        }

        pub fn entity(v: EntityUID) @This() {
            return .{ .entity = v };
        }

        /// returns true when both the type and value of a literal value matches with that of `other`
        pub fn eql(self: @This(), other: @This()) bool {
            return switch (self) {
                .bool => |v| switch (other) {
                    .bool => |vv| vv == v,
                    else => false,
                },
                .long => |v| switch (other) {
                    .long => |vv| vv == v,
                    else => false,
                },
                .string => |v| switch (other) {
                    .string => |vv| std.mem.eql(u8, v, vv),
                    else => false,
                },
                .entity => |v| switch (other) {
                    .entity => |vv| std.mem.eql(u8, v.type, vv.type) and std.mem.eql(u8, v.id, vv.id),
                    else => false,
                },
            };
        }
    };

    pub const Var = enum {
        principal,
        action,
        resource,
        context,
    };

    pub const UnaryOp = enum {
        not,
        neg,
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
    pattern: []const u8,
    slot: SlotId,
    ite: struct { @"if": *const Expr, then: *const Expr, @"else": *const Expr },
    @"and": struct { left: *const Expr, right: *const Expr },
    @"or": struct { left: *const Expr, right: *const Expr },
    unary: struct { op: UnaryOp, arg: *const Expr },
    binary: struct { op: BinaryOp, arg1: *const Expr, arg2: *const Expr },
    // todo: ext fn app
    // todo: get attr
    // todo: has attr
    // todo: like
    is: struct { expr: *const Expr, type: []const u8 }, // should we have a wrapper for EntityTypes?
    // todo: set
    set: []*const Expr,
    // todo: record
    unknown: void, // used for eval purposes, todo add some information

    /// Aggregate Expr types require pointers to other Exprs.
    /// Use this fn to promote those values onto heap allocated values
    /// callers are responsible for freeing allocated memory
    pub fn heapify(self: @This(), allocator: std.mem.Allocator) !*const @This() {
        const copy = try allocator.create(@This());
        copy.* = self;
        return copy;
    }

    pub fn literal(value: Literal) @This() {
        return .{ .literal = value };
    }

    pub fn variable(value: Var) @This() {
        return .{ .variable = value };
    }

    pub fn pattern(value: []const u8) @This() {
        return .{ .pattern = value };
    }

    pub fn slot(value: SlotId) @This() {
        return .{ .slot = value };
    }

    pub fn @"and"(l: *const Expr, r: *const Expr) @This() {
        return .{ .@"and" = .{ .left = l, .right = r } };
    }

    pub fn @"or"(l: Expr, r: Expr) @This() {
        return .{ .@"or" = .{ .left = &l, .right = &r } };
    }

    /// if .. then .. else ..
    pub fn ite(i: Expr, t: Expr, e: Expr) @This() {
        return .{
            .ite = .{ .@"if" = &i, .then = &t, .@"else" = &e },
        };
    }

    // unary ops

    pub fn neg(arg: Expr) @This() {
        return .{
            .unary = .{ .op = .neg, .arg = &arg },
        };
    }

    pub fn not(arg: Expr) @This() {
        return .{
            .unary = .{ .op = .not, .arg = &arg },
        };
    }

    // binary ops

    pub fn binary(op: BinaryOp, arg1: *const Expr, arg2: *const Expr) @This() {
        return .{
            // FIXME don't take address here
            .binary = .{ .op = op, .arg1 = arg1, .arg2 = arg2 },
        };
    }

    pub fn eq(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.eq, arg1, arg2);
    }

    pub fn lt(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.lt, arg1, arg2);
    }

    pub fn lte(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.lte, arg1, arg2);
    }

    pub fn add(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.add, arg1, arg2);
    }

    pub fn sub(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.sub, arg1, arg2);
    }

    pub fn mul(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.mul, arg1, arg2);
    }

    pub fn in(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.in, arg1, arg2);
    }

    pub fn contains(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.contains, arg1, arg2);
    }

    pub fn containsAll(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.contains_all, arg1, arg2);
    }

    pub fn containsAny(arg1: *const Expr, arg2: *const Expr) @This() {
        return binary(.contains_any, arg1, arg2);
    }

    pub fn isEntityType(expr: *const Expr, entityType: []const u8) @This() {
        return .{
            .is = .{ .expr = expr, .type = entityType },
        };
    }

    pub fn set(elems: []*const Expr) @This() {
        return .{ .set = elems };
    }

    // todo like and others

    pub fn unknown() @This() {
        return .{ .unknown = {} };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        switch (self) {
            .binary => |v| try writer.print("<{s} expr {} {s} {}>", .{ @tagName(self), v.arg1, @tagName(v.op), v.arg2 }),
            .literal => |v| try writer.print("<{s} expr {any}>", .{ @tagName(self), v }),
            .variable => |v| try writer.print("<{s} expr {s}>", .{ @tagName(self), @tagName(v) }),
            else => try writer.print("<{s} expr>", .{@tagName(self)}),
        }
    }
};

/// the core building block of permiting or denying access to perform an action against a given resource
pub const Policy = struct {
    id: []const u8, // typically derived when parsed as "policy{n}" where n is the index of the policy in parsed document
    annotations: []const Annotation,
    effect: Effect,
    scope: Scope,
    when: ?Expr = null,
    unless: ?Expr = null,
    //env: SlotEnv,

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

    pub fn condition(
        self: @This(),
        allocator: std.mem.Allocator,
    ) !Expr {
        // todo: include unless/when contexts where available
        return try self.scope.condition(allocator);
    }
};

pub const SlotEnv = std.AutoHashMap(SlotId, EntityUID);

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
    ancestors: []const EntityUID,

    /// return true if id is contained within ancestors
    pub fn isDecendantOf(self: @This(), id: EntityUID) bool {
        for (self.ancestors) |a| {
            if (a.eql(id)) {
                return true;
            }
        }
        return false;
    }
};

/// https://docs.cedarpolicy.com/auth/entities-syntax.html
pub const Entities = struct {
    pub const Mode = enum { concrete, partial };
    pub const Dereference = union(enum) {
        none: void,
        residual: Expr,
        data: Entity,
        fn get(self: @This()) ?Entity {
            return switch (self) {
                .data => |v| v,
                else => null,
            };
        }
    };
    const EntityMap = std.HashMap(
        EntityUID,
        Entity,
        struct {
            pub fn hash(_: @This(), key: EntityUID) u64 {
                var h = std.hash.Wyhash.init(0);
                h.update(key.type);
                h.update(key.id);
                return h.final();
            }

            pub fn eql(_: @This(), a: EntityUID, b: EntityUID) bool {
                return a.eql(b);
            }
        },
        std.hash_map.default_max_load_percentage,
    );

    // todo
    arena: *std.heap.ArenaAllocator,
    entities: EntityMap,
    mode: Mode = .concrete,

    fn init(arena: *std.heap.ArenaAllocator, entities: EntityMap, mode: Mode) @This() {
        return .{ .arena = arena, .entities = entities, .mode = mode };
    }

    /// get an entity by its id
    pub fn entity(self: @This(), id: EntityUID) Dereference {
        return if (self.entities.get(id)) |e|
            .{ .data = e }
        else switch (self.mode) {
            .concrete => .{ .none = {} },
            .partial => .{ .residual = Expr.unknown() },
        };
    }

    // todo: pass along schema where this is one and validate what was parsed is actually expected
    pub fn fromJson(allocator: std.mem.Allocator, source: []const u8) !Entities {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        const parsed = try std.json.parseFromSliceLeaky([]const EntityJson, arena.allocator(), source, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        });
        var entities = EntityMap.init(arena.allocator());
        for (parsed) |e| {
            const id = e.uid.normalize();
            var parents = try std.ArrayList(EntityUID).initCapacity(arena.allocator(), e.parents.len);
            for (e.parents) |p| {
                parents.appendAssumeCapacity(p.normalize());
            }
            try entities.put(id, .{ .uuid = id, .ancestors = try parents.toOwnedSlice() });
        }
        return init(arena, entities, .concrete);
    }

    pub fn deinit(self: *@This()) void {
        const alloc = self.arena.child_allocator;
        self.arena.deinit();
        alloc.destroy(self.arena);
    }
};

test Entities {
    const allocator = std.testing.allocator;
    var entities = try Entities.fromJson(allocator,
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
        \\    }
        \\]
    );
    defer entities.deinit();
    try std.testing.expectEqualDeep(EntityUID.init("User", "alice"), entities.entity(EntityUID.init("User", "alice")).get().?.uuid);
    try std.testing.expect(entities.entity(EntityUID.init("User", "ahmad")).get() == null);
}

/// https://docs.cedarpolicy.com/auth/entities-syntax.html#entities
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
