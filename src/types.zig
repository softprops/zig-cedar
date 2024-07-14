const std = @import("std");

/// identifies an entity within the system
pub const EntityUID = struct {
    ty: []const u8,
    id: []const u8,
    pub fn init(ty: []const u8, id: []const u8) @This() {
        return .{ .ty = ty, .id = id };
    }

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        try writer.print("{s}::\"{s}\"", .{ self.ty, self.id });
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

pub const Entities = struct {
    pub const Mode = enum { concrete, partial };

    // todo
    //allocator: std.mem.Allocator,
    //entities: std.AutoHashMap(EntityUID, Entity),
    mode: Mode = .concrete,
};

pub const Schema = struct {
    // todo
};

pub const Context = struct {
    // todo
};
