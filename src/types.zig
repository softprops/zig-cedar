const std = @import("std");

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

pub const Policy = struct {
    annotations: []const Annotation,
    effect: Effect,
    scope: Scope,
    // todo conditions

    pub fn format(
        self: @This(),
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        for (self.annotations) |a| {
            try writer.print("{s}\n", .{a});
        }
        try writer.print("{s}{s};", .{ @tagName(self.effect), self.scope });
    }
};

pub const PolicySet = struct {
    arena: *std.heap.ArenaAllocator,
    policies: []const Policy,
    pub fn deinit(self: *@This()) void {
        const alloc = self.arena.child_allocator;
        self.arena.deinit();
        alloc.destroy(self.arena);
    }
};
